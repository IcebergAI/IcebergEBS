"""alertdestination kind + config (outbound integrations)

Generalise AlertDestination for multi-kind delivery (#37): a ``kind`` column
(webhook | slack | teams | email | jira | servicenow) and a ``config`` JSON-in-str
column for kind-specific non-secret extras. Existing rows are webhook destinations,
so both columns get a server default and no backfill is needed. A CHECK constraint
backstops the kind enum at the schema level (the #217/#218 pattern), held in lockstep
with the app/senders registry by tests/test_senders.py.

Revision ID: a3b4c5d6e7f8
Revises: c9d0e1f2a3b4
Create Date: 2026-07-20 10:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
import sqlmodel

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a3b4c5d6e7f8"
down_revision: Union[str, None] = "c9d0e1f2a3b4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_KIND_CHECK = "kind IN ('webhook', 'slack', 'teams', 'email', 'jira', 'servicenow')"


def upgrade() -> None:
    # server_default fills existing rows (all webhook destinations) and any writer
    # that bypasses the ORM; the ORM always sets both columns explicitly.
    op.add_column(
        "alertdestination",
        sa.Column("kind", sqlmodel.sql.sqltypes.AutoString(), nullable=False, server_default="webhook"),
    )
    op.add_column(
        "alertdestination",
        sa.Column("config", sqlmodel.sql.sqltypes.AutoString(), nullable=False, server_default="{}"),
    )
    op.create_check_constraint("ck_alertdestination_kind", "alertdestination", _KIND_CHECK)


def downgrade() -> None:
    # Drop the added structure only — never touch user rows.
    op.drop_constraint("ck_alertdestination_kind", "alertdestination", type_="check")
    op.drop_column("alertdestination", "config")
    op.drop_column("alertdestination", "kind")
