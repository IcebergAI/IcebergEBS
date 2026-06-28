"""convert all timestamp columns to timezone-aware (timestamptz)

The app writes timezone-aware UTC datetimes (see app.models._utcnow). A plain
``TIMESTAMP WITHOUT TIME ZONE`` column rejects those under asyncpg, so every
timestamp column moves to ``TIMESTAMP WITH TIME ZONE``. Existing naive values are
interpreted as UTC during the conversion.

Revision ID: a1b2c3d4e5f6
Revises: f9849169d73f
Create Date: 2026-06-28 05:40:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, None] = "f9849169d73f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# (table, column, nullable) for every timestamp column in the schema.
_COLUMNS = [
    ("user", "created_at", False),
    ("user", "password_changed_at", True),
    ("extension", "last_updated", True),
    ("extension", "added_at", False),
    ("extension", "last_fetched_at", True),
    ("fetchlog", "fetched_at", False),
    ("installcounthistory", "recorded_at", False),
    ("alertdestination", "created_at", False),
    ("alertrule", "created_at", False),
    ("apikey", "created_at", False),
    ("apikey", "last_used_at", True),
    ("alertlog", "sent_at", False),
]


def upgrade() -> None:
    for table, column, nullable in _COLUMNS:
        op.alter_column(
            table,
            column,
            type_=sa.DateTime(timezone=True),
            existing_type=sa.DateTime(),
            existing_nullable=nullable,
            postgresql_using=f"{column} AT TIME ZONE 'UTC'",
        )


def downgrade() -> None:
    for table, column, nullable in _COLUMNS:
        op.alter_column(
            table,
            column,
            type_=sa.DateTime(),
            existing_type=sa.DateTime(timezone=True),
            existing_nullable=nullable,
            postgresql_using=f"{column} AT TIME ZONE 'UTC'",
        )
