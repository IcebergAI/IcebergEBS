"""The account page's destination-kind descriptors must reach the browser (#311).

`routes/ui.py` passes `destination_kinds` into the template context and
`senders/base.py:kind_descriptors` documents itself as feeding "both the
``GET /api/alerts/destination-kinds`` endpoint and the account-page JSON island" —
but the island only serialised destinations/rules/extensions/alert_log, so
`data.destination_kinds` was undefined in `accountPrefs` and `destinationKinds`
fell back to `[]`. The Type dropdown rendered zero options and, because
`kindConfigFields` derives from the same list, no kind-specific config fields
rendered either: no Slack/Teams/email/Jira/ServiceNow destination could be created
from the UI at all.

The island is the only path — the page never calls the API endpoint — so a test on
the endpoint alone would not have caught this.
"""

import json
import re

from app.senders.base import kind_descriptors

ISLAND_RE = re.compile(
    r'<script id="account-data" type="application/json">(.*?)</script>',
    re.DOTALL,
)


def _island(html: str) -> dict:
    m = ISLAND_RE.search(html)
    assert m, "account-data JSON island missing from the page"
    return json.loads(m.group(1))


async def test_account_island_carries_destination_kinds(client):
    r = await client.get("/account")
    assert r.status_code == 200
    data = _island(r.text)

    assert "destination_kinds" in data, (
        "the Type dropdown reads destinationKinds from this island; without the key it renders no options"
    )
    assert data["destination_kinds"], "at least the built-in kinds must be present"


async def test_island_kinds_match_the_server_descriptors(client):
    """The island must carry the same descriptors the API serves, so the dynamic
    form and API/SOAR consumers stay on one source."""
    r = await client.get("/account")
    assert _island(r.text)["destination_kinds"] == json.loads(json.dumps(kind_descriptors()))


async def test_island_kinds_carry_the_fields_the_form_binds(client):
    """`x-for="k in destinationKinds"` binds :value=k.kind / x-text=k.label, and the
    getters read target_label, config_fields, available, unavailable_reason."""
    r = await client.get("/account")
    kinds = _island(r.text)["destination_kinds"]
    for k in kinds:
        for field in ("kind", "label", "target_label", "config_fields", "available"):
            assert field in k, f"{k.get('kind', '?')} missing {field}"
        assert isinstance(k["config_fields"], list)


async def test_webhook_kind_is_present(client):
    """destForm.kind defaults to 'webhook', so that descriptor must exist or the
    default selection resolves to null and targetLabel degrades to 'Target'."""
    r = await client.get("/account")
    kinds = _island(r.text)["destination_kinds"]
    assert "webhook" in {k["kind"] for k in kinds}
