#!/usr/bin/env bash
# Exercise the chart's Bitnami-to-owned-Postgres upgrade guard (#276).
#
# The guard uses Helm's `lookup`, which returns empty without a cluster — so it
# cannot be tested by rendering the chart normally, and a test that only greps
# the template for guard-shaped strings proves nothing about its behaviour.
# Instead, substitute a fixture for the lookup line and assert what each branch
# actually does:
#
#   * a foreign StatefulSet (no marker label)                 -> must refuse
#   * a foreign one whose image name lacks "bitnami"          -> must refuse
#     (an air-gapped mirror; this is why the guard uses a positive marker
#      rather than sniffing the image string)
#   * this chart's own StatefulSet (marker present)           -> must render
#
# Run from the repo root. Requires helm and python3 on PATH.
#
# shellcheck disable=SC2016
# The single-quoted strings below are Go template literals handed to Helm, not
# shell: `$existing` is a template variable and must not be expanded here.

set -euo pipefail

CHART="${CHART:-helm/iceberg-ebs}"
WORK="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/iceberg-upgrade-guard"
LOOKUP='{{- $existing := lookup "apps/v1" "StatefulSet" .Release.Namespace (include "iceberg-ebs.postgresql.fullname" .) -}}'

# Render the chart with the guard's `lookup` replaced by $1. Output lands in
# $WORK/out. Setup runs under `set -e` so a broken harness fails loudly instead
# of producing an empty render that reads as "the guard did not fire".
render_with() {
  rm -rf "$WORK"
  cp -r "$CHART" "$WORK"
  python3 - "$WORK/templates/postgres.yaml" "$LOOKUP" "$1" <<'PY'
import pathlib, sys
path, lookup, replacement = sys.argv[1], sys.argv[2], sys.argv[3]
p = pathlib.Path(path)
text = p.read_text()
if lookup not in text:
    sys.exit("guard lookup line not found — did templates/postgres.yaml change?")
p.write_text(text.replace(lookup, replacement))
PY
  # helm exits non-zero when `fail` fires, which is the expected path for two of
  # the three cases; let the assertions below judge the output.
  helm template ci "$WORK" \
    --set image.tag=v0.0.0-ci \
    --set icebergEbs.adminPassword=x \
    --set icebergEbs.secretKey=y \
    --set postgresql.auth.password=z \
    >"$WORK/out" 2>&1 || true
  test -s "$WORK/out"  # empty output means the harness broke, not a verdict
}

FOREIGN='{{- $existing := dict "metadata" (dict "labels" (dict "app.kubernetes.io/name" "postgresql")) -}}'
MIRRORED='{{- $existing := dict "metadata" (dict "labels" (dict "app" "pg")) "spec" (dict "template" (dict "spec" (dict "containers" (list (dict "image" "registry.internal/pg:16"))))) -}}'
OURS='{{- $existing := dict "metadata" (dict "labels" (dict "icebergai.io/postgres-template" "iceberg-ebs")) -}}'

for fixture in "$FOREIGN" "$MIRRORED"; do
  render_with "$fixture"
  if ! grep -q "Refusing to upgrade" "$WORK/out"; then
    echo "FAIL: guard did not refuse a foreign StatefulSet" >&2
    echo "  fixture: $fixture" >&2
    cat "$WORK/out" >&2
    exit 1
  fi
done

# ...and it must not refuse our own, or every upgrade would be blocked.
render_with "$OURS"
if ! grep -q "kind: StatefulSet" "$WORK/out"; then
  echo "FAIL: guard refused the chart's own StatefulSet" >&2
  cat "$WORK/out" >&2
  exit 1
fi

rm -rf "$WORK"
echo "upgrade guard OK: refuses foreign StatefulSets (including mirrored images), allows its own"
