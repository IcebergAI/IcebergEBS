"""add known-bad extension threat-list entries (#31).

Revision ID: c5d6e7f8a9b0
Revises: b4c5d6e7f8a9
Create Date: 2026-08-12 09:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
import sqlmodel

from alembic import op

revision: str = "c5d6e7f8a9b0"
down_revision: Union[str, None] = "b4c5d6e7f8a9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("extension", sa.Column("threat_match", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.alter_column("extension", "threat_match", server_default=None)
    op.create_table(
        "threatlistentry",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("store", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("extension_id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("source", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("reason", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        # Core PostgreSQL upserts do not apply SQLModel's Python default.
        # Keep a database default for direct/feed inserts as well.
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.CheckConstraint("store IN ('chrome', 'vscode', 'edge')", name="ck_threatlistentry_store"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("store", "extension_id", "source", name="uq_threatlistentry_identity"),
    )
    op.create_index("ix_threatlistentry_extension", "threatlistentry", ["store", "extension_id"], unique=False)


def downgrade() -> None:
    op.drop_column("extension", "threat_match")
    op.drop_index("ix_threatlistentry_extension", table_name="threatlistentry")
    op.drop_table("threatlistentry")
