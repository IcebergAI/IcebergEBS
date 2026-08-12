"""add extension triage and analyst risk overrides (#39).

Revision ID: d6e7f8a9b0c1
Revises: c5d6e7f8a9b0
Create Date: 2026-08-12 12:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
import sqlmodel

from alembic import op

revision: str = "d6e7f8a9b0c1"
down_revision: Union[str, None] = "c5d6e7f8a9b0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "extension",
        sa.Column("heuristic_risk_score", sa.Integer(), nullable=True),
    )
    op.add_column(
        "extension",
        sa.Column(
            "triage_status",
            sqlmodel.sql.sqltypes.AutoString(),
            nullable=False,
            server_default="new",
        ),
    )
    op.add_column("extension", sa.Column("triage_assignee", sqlmodel.sql.sqltypes.AutoString(), nullable=True))
    op.add_column("extension", sa.Column("triage_notes", sqlmodel.sql.sqltypes.AutoString(), nullable=True))
    op.add_column(
        "extension",
        sa.Column(
            "risk_override",
            sqlmodel.sql.sqltypes.AutoString(),
            nullable=False,
            server_default="none",
        ),
    )
    op.add_column("extension", sa.Column("triage_updated_at", sa.DateTime(timezone=True), nullable=True))
    op.execute(
        sa.text(
            "UPDATE extension SET heuristic_risk_score = "
            "CASE WHEN threat_match THEN NULL ELSE risk_score END, "
            "triage_updated_at = added_at"
        )
    )
    op.create_check_constraint(
        "ck_extension_triage_status",
        "extension",
        "triage_status IN ('new', 'triaging', 'accepted-risk', 'blocked', 'resolved')",
    )
    op.create_check_constraint(
        "ck_extension_risk_override",
        "extension",
        "risk_override IN ('none', 'allow', 'deny')",
    )
    op.create_check_constraint(
        "ck_extension_heuristic_risk_score",
        "extension",
        "heuristic_risk_score IS NULL OR (heuristic_risk_score >= 0 AND heuristic_risk_score <= 100)",
    )
    op.create_index(
        "ix_extension_user_triage_status",
        "extension",
        ["user_id", "triage_status"],
        unique=False,
    )
    op.alter_column("extension", "triage_status", server_default=None)
    op.alter_column("extension", "risk_override", server_default=None)


def downgrade() -> None:
    op.drop_index("ix_extension_user_triage_status", table_name="extension")
    op.drop_constraint("ck_extension_heuristic_risk_score", "extension", type_="check")
    op.drop_constraint("ck_extension_risk_override", "extension", type_="check")
    op.drop_constraint("ck_extension_triage_status", "extension", type_="check")
    op.drop_column("extension", "triage_updated_at")
    op.drop_column("extension", "risk_override")
    op.drop_column("extension", "triage_notes")
    op.drop_column("extension", "triage_assignee")
    op.drop_column("extension", "triage_status")
    op.drop_column("extension", "heuristic_risk_score")
