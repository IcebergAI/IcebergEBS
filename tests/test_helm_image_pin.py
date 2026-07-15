"""Regression tests for #88: the Helm chart refuses to deploy a mutable :latest."""

from pathlib import Path

import yaml

_CHART = Path(__file__).resolve().parent.parent / "helm" / "iceberg-ebs"


def test_values_image_tag_has_no_default():
    values = yaml.safe_load((_CHART / "values.yaml").read_text())
    # Empty (not "latest"): an operator must pin an immutable tag explicitly.
    assert values["image"]["tag"] == ""
    # IfNotPresent is correct *because* the pinned tag is immutable.
    assert values["image"]["pullPolicy"] == "IfNotPresent"


def test_deployment_requires_image_tag():
    d = (_CHART / "templates" / "deployment.yaml").read_text()
    # The `image:` line must guard the tag with `required` so an empty value fails the
    # render instead of deploying :latest.
    image_line = next(ln for ln in d.splitlines() if ln.lstrip().startswith("image:"))
    assert "required" in image_line
    assert ".Values.image.tag" in image_line
