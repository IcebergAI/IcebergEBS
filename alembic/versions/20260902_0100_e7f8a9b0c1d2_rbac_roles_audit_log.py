"""RBAC role enum replacing User.is_admin (#33) + append-only audit log (#34).

Revision ID: e7f8a9b0c1d2
Revises: d6e7f8a9b0c1
Create Date: 2026-09-02 01:00:00.000000

Backfill: ``is_admin = true`` → ``admin``; everything else → ``analyst`` (the
pre-RBAC "regular user" level — today's non-admins keep the ability to add and
triage extensions; only destination/rule management, which was previously open
to every user, moves behind the admin role, per the #33 acceptance criteria).

Downgrade restores ``is_admin`` from ``role`` (admin → true, else false) and
NEVER deletes user rows (the #218 rule); an auditor simply becomes a regular
user again. The audit table is dropped on downgrade — it has no pre-#34
representation to fall back to.
"""

from typing import Sequence, Union

import sqlalchemy as sa
import sqlmodel

from alembic import op

revision: str = "e7f8a9b0c1d2"
down_revision: Union[str, None] = "d6e7f8a9b0c1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- User.role (#33) -------------------------------------------------------
    op.add_column(
        "user",
        sa.Column("role", sqlmodel.sql.sqltypes.AutoString(), nullable=False, server_default="analyst"),
    )
    op.execute(sa.text("UPDATE \"user\" SET role = CASE WHEN is_admin THEN 'admin' ELSE 'analyst' END"))
    op.create_check_constraint("ck_user_role", "user", "role IN ('admin', 'analyst', 'auditor')")
    op.create_index("ix_user_role", "user", ["role"], unique=False)
    # The model default (analyst) applies at the ORM layer; drop the DDL default so
    # the two can't drift silently (same discipline as the triage migration).
    op.alter_column("user", "role", server_default=None)
    op.drop_column("user", "is_admin")

    # --- AuditLog (#34) ------------------------------------------------------------
    op.create_table(
        "auditlog",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("actor_id", sa.Integer(), nullable=True),
        sa.Column("actor", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("action", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("target_type", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("target_id", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("detail", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("ip", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["actor_id"], ["user.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_auditlog_actor_id", "auditlog", ["actor_id"], unique=False)
    op.create_index("ix_auditlog_at_desc", "auditlog", [sa.text("at DESC"), sa.text("id DESC")], unique=False)
    op.create_index("ix_auditlog_target", "auditlog", ["target_type", "target_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_auditlog_target", table_name="auditlog")
    op.drop_index("ix_auditlog_at_desc", table_name="auditlog")
    op.drop_index("ix_auditlog_actor_id", table_name="auditlog")
    op.drop_table("auditlog")

    op.add_column("user", sa.Column("is_admin", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.execute(sa.text("UPDATE \"user\" SET is_admin = (role = 'admin')"))
    op.alter_column("user", "is_admin", server_default=None)
    op.drop_index("ix_user_role", table_name="user")
    op.drop_constraint("ck_user_role", "user", type_="check")
    op.drop_column("user", "role")
