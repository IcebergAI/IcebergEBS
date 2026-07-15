"""add FetchLog.store_outage

Fetcher resilience (#108): a per-store circuit breaker records a ``store_outage``
FetchLog when it skips an extension because the store had N consecutive failures
this cycle, so the dashboard can tell "the store was down" apart from "this
extension is broken". Added with a ``server_default`` of false so the ALTER is
safe against existing rows; the model carries no server default, but the migration
test compares types only (not server defaults), so head still matches models.

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-07-15 08:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d4e5f6a7b8c9"
down_revision: Union[str, None] = "c3d4e5f6a7b8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "fetchlog",
        sa.Column("store_outage", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("fetchlog", "store_outage")
