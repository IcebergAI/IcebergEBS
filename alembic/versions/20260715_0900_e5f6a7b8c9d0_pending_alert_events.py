"""add Extension.pending_alert_events

Graceful shutdown / recoverable alerts (#109): a nullable JSON column holding change
events staged atomically with a state change, so an alert missed because the process
died between the commit and webhook delivery is re-fired on the next scheduler cycle
instead of being silently dropped. Chains off the store_outage migration (#108).

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-07-15 09:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
import sqlmodel

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e5f6a7b8c9d0"
down_revision: Union[str, None] = "d4e5f6a7b8c9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("extension", sa.Column("pending_alert_events", sqlmodel.sql.sqltypes.AutoString(), nullable=True))


def downgrade() -> None:
    op.drop_column("extension", "pending_alert_events")
