"""add immutable package snapshots for risky update detection (#30).

Revision ID: b4c5d6e7f8a9
Revises: a3b4c5d6e7f8
Create Date: 2026-08-11 09:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
import sqlmodel

from alembic import op

revision: str = "b4c5d6e7f8a9"
down_revision: Union[str, None] = "a3b4c5d6e7f8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "packagesnapshot",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("extension_id", sa.Integer(), nullable=False),
        sa.Column("version", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("package_sha256", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("analysis_json", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["extension_id"], ["extension.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("extension_id", "version", name="uq_package_snapshot_extension_version"),
    )
    op.create_index("ix_packagesnapshot_extension_id", "packagesnapshot", ["extension_id"], unique=False)
    op.create_index(
        "ix_package_snapshot_extension_captured",
        "packagesnapshot",
        ["extension_id", sa.text("captured_at DESC"), sa.text("id DESC")],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_package_snapshot_extension_captured", table_name="packagesnapshot")
    op.drop_index("ix_packagesnapshot_extension_id", table_name="packagesnapshot")
    op.drop_table("packagesnapshot")
