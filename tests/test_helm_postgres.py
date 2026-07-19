"""The Helm chart's database wiring must actually resolve (#276).

None of this was reachable by any existing gate: nothing in CI renders or installs
the chart, so a Deployment referencing a Secret that never exists looked fine in
review and failed only at ``CreateContainerConfigError`` on a real cluster.

The original trap was subchart naming. ``iceberg-ebs.fullname`` is
``<release>-iceberg-ebs``, but a subchart's ``common.names.fullname`` uses its *own*
chart name, so the Bitnami postgresql subchart created ``<release>-postgresql``. The
chart asked for ``<release>-iceberg-ebs-postgresql`` — a Secret and a Service that are
never created, so the pod could not start and could not have resolved the DB host
either.

The subchart itself is gone now (Broadcom's 2025 Bitnami catalog migration left its
pinned image unpullable and its successor unable to pin a PostgreSQL version on the
free tier), but the resource *names* were kept, so these tests still guard the same
contract — and the naming test now protects a helper rather than an assumption about
someone else's chart.

These tests read the templates as text rather than rendering them (no helm binary in
the test environment); the CI ``helm`` job does the real ``helm template`` render.
Between them: this file fails fast on the naming contract, CI proves it renders.
"""

from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parent.parent
_CHART = _ROOT / "helm/iceberg-ebs"
_DEPLOYMENT = _CHART / "templates/deployment.yaml"
_HELPERS = _CHART / "templates/_helpers.tpl"
_SECRET = _CHART / "templates/secret.yaml"
_COMPOSE = _ROOT / "docker-compose.yml"
_DEPLOYMENT_DOC = _ROOT / "DEPLOYMENT.md"


def _values() -> dict:
    return yaml.safe_load((_CHART / "values.yaml").read_text())


def _chart() -> dict:
    return yaml.safe_load((_CHART / "Chart.yaml").read_text())


def test_postgres_helper_is_release_scoped_not_chart_scoped():
    """The helper must mirror the subchart's own naming: <release>-postgresql."""
    helpers = _HELPERS.read_text()
    assert '{{- define "iceberg-ebs.postgresql.fullname" -}}' in helpers
    assert 'printf "%s-postgresql" .Release.Name' in helpers
    # A fixed fullnameOverride would collide between two releases in one namespace,
    # so the release-scoped form must be the default, not the override.
    assert ".Values.postgresql.fullnameOverride" in helpers


def test_deployment_references_the_subchart_name_for_secret_and_host():
    """The regression itself: never `iceberg-ebs.fullname` + "-postgresql"."""
    text = _DEPLOYMENT.read_text()
    assert '{{ include "iceberg-ebs.fullname" . }}-postgresql' not in text, (
        "references the app fullname + -postgresql; the Bitnami subchart names its "
        "resources <release>-postgresql, so this Secret/Service never exists (#276)"
    )
    assert text.count('include "iceberg-ebs.postgresql.fullname"') >= 2  # secretKeyRef + DSN host


def test_bundled_postgres_is_gated_and_owned_by_this_chart():
    """The Bitnami subchart is gone (#276): its `postgresql.enabled` value was
    inert without a `condition:`, and after Broadcom's 2025 catalog migration its
    pinned image no longer pulls at all. templates/postgres.yaml carries the
    database now, gated by a plain `if`, which cannot be inert."""
    assert "dependencies" not in _chart(), "the Bitnami subchart should no longer be a dependency"
    assert _values()["postgresql"]["enabled"] is True
    assert "{{- if .Values.postgresql.enabled }}" in (_CHART / "templates/postgres.yaml").read_text()


def test_bundled_postgres_uses_the_upstream_image_not_bitnami():
    """Bitnami's versioned tags moved to `bitnamilegacy` and its free catalog now
    publishes `latest` only — a moving tag that could roll a running deployment
    onto a new PostgreSQL major on pod restart."""
    image = _values()["postgresql"]["image"]
    assert image["repository"] == "postgres"
    assert "bitnami" not in image["repository"]


def test_bundled_postgres_requires_a_password():
    text = (_CHART / "templates/postgres.yaml").read_text()
    assert "postgresql.auth.password is required when postgresql.enabled=true" in text


def test_external_database_knob_exists_and_defaults_to_the_bundled_db():
    external = _values()["externalDatabase"]
    assert external["url"] == ""
    assert external["existingSecret"] == ""
    assert external["existingSecretKey"] == "database-url"


def test_external_database_dsn_is_only_ever_read_from_a_secret():
    """The DSN carries the password: it must never land in the ConfigMap, and never
    as a plaintext `value:` in the pod spec."""
    configmap = (_CHART / "templates/configmap.yaml").read_text()
    assert "ICEBERG_EBS_DATABASE_URL" not in configmap
    assert "externalDatabase" not in configmap

    deployment = _DEPLOYMENT.read_text()
    assert ".Values.externalDatabase.url" not in deployment  # secret.yaml's job, not the pod spec's
    assert ".Values.externalDatabase.existingSecret" in deployment


def test_external_database_without_a_dsn_fails_the_render():
    """Refusing to render beats deploying a pod that cannot reach a database."""
    secret = _SECRET.read_text()
    assert "externalDatabase.url is required when postgresql.enabled=false" in secret
    assert "required" in secret


def test_chart_appversion_matches_the_application_version():
    """appVersion advertises what the chart deploys; "1.0.0" against an 0.1.0b1 app
    is a cosmetic lie that misleads `helm list`."""
    pyproject = (_ROOT / "pyproject.toml").read_text()
    version = next(
        line.split("=", 1)[1].strip().strip('"') for line in pyproject.splitlines() if line.startswith("version =")
    )
    assert str(_chart()["appVersion"]) == version


def test_deployment_docs_do_not_reproduce_the_bug_they_describe():
    """DEPLOYMENT.md embeds excerpts of the chart files, so it is a second copy that
    drifts silently — its examples still showed the broken secret reference and the
    wrong appVersion after the chart was fixed. Guard the specific strings."""
    doc = _DEPLOYMENT_DOC.read_text()
    assert '{{ include "iceberg-ebs.fullname" . }}-postgresql' not in doc, (
        "the docs still show the pre-#276 secret/host reference, which names a resource nothing creates"
    )
    assert 'appVersion: "1.0.0"' not in doc
    assert "charts.bitnami.com" not in doc


def test_migration_guard_identifies_our_statefulset_positively():
    """A `helm upgrade` over the Bitnami subchart would bind its PVC, find no
    pgdata, and initdb an EMPTY database while every probe stayed green. The chart
    must refuse rather than rely on the operator reading the runbook first.

    The recognition must be a **positive marker**, not an image-name sniff: the
    subchart supported registry overrides, so a mirrored `registry.internal/pg:16`
    carries the old layout with no "bitnami" anywhere in the string. Anything
    lacking our label predates this template, whatever it is called.

    The guard's actual branch behaviour is exercised by the CI `helm` job (it
    needs a real render with a substituted `lookup`); this asserts the contract
    those two halves share.
    """
    text = (_CHART / "templates/postgres.yaml").read_text()
    assert 'lookup "apps/v1" "StatefulSet"' in text
    assert 'contains "bitnami"' not in text, "image-name sniffing is bypassable by a mirrored registry"
    assert 'dig "metadata" "labels" "icebergai.io/postgres-template"' in text
    # The marker must actually be stamped on the StatefulSet, or the guard blocks
    # every upgrade including its own.
    assert "icebergai.io/postgres-template: iceberg-ebs" in text
    # ...and on metadata only: a StatefulSet's selector is immutable.
    assert "icebergai.io/postgres-template" not in text.split("selector:", 1)[1].split("template:", 1)[0]
    # The failure must name the runbook, and the runbook must exist.
    assert "Migrating from the Bitnami subchart" in text
    assert "#### Migrating from the Bitnami subchart" in _DEPLOYMENT_DOC.read_text()


def test_migration_runbook_verifies_the_dump_by_restoring_it():
    """`pg_restore --list` only parses the table of contents: an archive truncated
    after its TOC passes while missing every data block. Deleting a PVC on that
    basis is unrecoverable, so the runbook must restore into a scratch database
    and compare row counts, and must retain the PV before deleting the claim."""
    doc = _DEPLOYMENT_DOC.read_text()
    runbook = doc.split("#### Migrating from the Bitnami subchart", 1)[1].split("\n## ", 1)[0]
    assert "set -euo pipefail" in runbook, "a failed pg_dump must not look like a successful one"
    assert "migration_verify" in runbook, "the dump must be verified by restoring it, not by reading its TOC"
    assert "persistentVolumeReclaimPolicy" in runbook, "the PV must be retained before the PVC is deleted"
    assert "delete pvc" in runbook
    # Retain must come before the delete, or the data is already gone.
    assert runbook.index("persistentVolumeReclaimPolicy") < runbook.index("delete pvc")


def test_chart_version_was_bumped_for_the_template_rewrite():
    """Reusing a chart version across materially different templates makes packaged
    chart artifacts ambiguous."""
    assert _chart()["version"] != "0.1.0"


def _compose_postgres_image() -> str:
    return yaml.safe_load(_COMPOSE.read_text())["services"]["postgres"]["image"]


def test_helm_postgres_image_matches_compose_exactly():
    """Lockstep guard, mirroring test_helm_caddy.py (#200).

    Compose, the backup service and the CI test container all pin one Postgres
    image; the Helm path must run the *same* one, or a version difference shows
    up only in production — and a dump taken from one is not guaranteed to
    restore into the other. Since #276 dropped the Bitnami subchart in favour of
    the upstream image, the two are literally the same reference, so this can be
    an exact match rather than a major-version approximation.

    Dependabot's `docker-compose` ecosystem bumps the Compose pin but cannot see
    Helm values, so this test is the only thing that forces the chart to follow.
    Bump both in the same PR.
    """
    image = _values()["postgresql"]["image"]
    pinned = f"{image['repository']}:{image['tag']}"
    assert pinned == _compose_postgres_image(), (
        f"Helm postgres image {pinned!r} and the Compose image "
        f"{_compose_postgres_image()!r} have drifted — bump both together"
    )
