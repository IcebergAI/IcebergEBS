"""proxysettings mode check

Revision ID: 39d4509e2a67
Revises: b7c8d9e0f1a2
Create Date: 2026-07-18 17:20:16.599236
"""

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "39d4509e2a67"
down_revision: Union[str, None] = "b7c8d9e0f1a2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Constrain mode to the exact ProxyMode enum so a junk/lowercase value can't be
    # persisted and silently fail open to direct egress (#230), mirroring the
    # OIDCSettings.auth_mode CHECK (#218).
    #
    # Normalise existing data first, because the whole point of this CHECK is that a
    # writer bypassing the app layer (raw SQL, a direct update_settings before #230)
    # may already have persisted a lowercase/junk mode. This MUST be a single atomic
    # UPDATE with a CASE, not a sequence of statements: canonicalising case first
    # (`'explicit'` → `'EXPLICIT'`) on a legacy EXPLICIT-with-empty-URL row would write
    # an intermediate value the existing ck_proxysettings_explicit_requires_url rejects
    # mid-statement, aborting the migration before any repair could run (#230 review).
    # The CASE computes each row's final, always-valid value in one write:
    #   - uppercase + trim so 'explicit' / ' SYSTEM ' become canonical;
    #   - a value still outside the enum → SYSTEM (the seed default, matching
    #     resolve_proxy_url's fallback for an unknown mode);
    #   - a would-be EXPLICIT with an empty proxy_url (the fail-open state) → SYSTEM,
    #     so the EXPLICIT⇒URL constraint holds against the written value.
    op.execute(
        """
        UPDATE proxysettings SET mode = CASE
            WHEN UPPER(TRIM(mode)) NOT IN ('NONE', 'SYSTEM', 'EXPLICIT') THEN 'SYSTEM'
            WHEN UPPER(TRIM(mode)) = 'EXPLICIT' AND COALESCE(TRIM(proxy_url), '') = '' THEN 'SYSTEM'
            ELSE UPPER(TRIM(mode))
        END
        """
    )
    op.create_check_constraint("ck_proxysettings_mode", "proxysettings", "mode IN ('NONE', 'SYSTEM', 'EXPLICIT')")


def downgrade() -> None:
    # Drop only the enum CHECK. The normalisation above is a one-way data repair and is
    # deliberately not reverted — no rows are deleted or otherwise destroyed.
    op.drop_constraint("ck_proxysettings_mode", "proxysettings", type_="check")
