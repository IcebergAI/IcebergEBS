"""add InstallObservation + Extension.install_footprint

SOAR-fed org inventory (#29): a new ``installobservation`` table (one row per
extension+asset, unique on that pair so re-pushes upsert) and a cached
``install_footprint`` (distinct asset count) on ``extension``. New timestamp
columns are created as ``timestamptz`` directly (the app writes tz-aware UTC),
and the FK to ``extension`` carries ``ON DELETE CASCADE`` like the other
per-extension history tables.

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-06-30 09:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
import sqlmodel

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c3d4e5f6a7b8"
down_revision: Union[str, None] = "b2c3d4e5f6a7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("extension", sa.Column("install_footprint", sa.Integer(), nullable=True))

    op.create_table(
        "installobservation",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("extension_id", sa.Integer(), nullable=False),
        sa.Column("asset_id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("asset_type", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("department", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("source", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["extension_id"], ["extension.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("extension_id", "asset_id"),
    )
    with op.batch_alter_table("installobservation", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_installobservation_extension_id"), ["extension_id"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("installobservation", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_installobservation_extension_id"))
    op.drop_table("installobservation")
    op.drop_column("extension", "install_footprint")
