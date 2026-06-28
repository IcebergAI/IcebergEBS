"""add ON DELETE actions to foreign keys

Pushes referential cleanup into the schema (the SQLModel-recommended pattern):
SET NULL on the history FKs that must survive a parent delete (AlertLog → rule /
destination / user, Extension → user), CASCADE on the children that are removed
with their parent (config rows + per-extension history). This replaces the manual
FK-severing the delete handlers used to do.

The baseline created these FKs unnamed, so Postgres assigned the conventional
``<table>_<column>_fkey`` names, which we drop and recreate with the action.

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-06-28 06:10:00.000000
"""

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b2c3d4e5f6a7"
down_revision: Union[str, None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# (table, column, referent_table, referent_column, ondelete)
_FKS = [
    ("extension", "user_id", "user", "id", "SET NULL"),
    ("alertdestination", "user_id", "user", "id", "CASCADE"),
    ("alertrule", "user_id", "user", "id", "CASCADE"),
    ("alertrule", "destination_id", "alertdestination", "id", "CASCADE"),
    ("alertrule", "extension_id", "extension", "id", "CASCADE"),
    ("apikey", "user_id", "user", "id", "CASCADE"),
    ("fetchlog", "extension_id", "extension", "id", "CASCADE"),
    ("installcounthistory", "extension_id", "extension", "id", "CASCADE"),
    ("alertlog", "rule_id", "alertrule", "id", "SET NULL"),
    ("alertlog", "destination_id", "alertdestination", "id", "SET NULL"),
    ("alertlog", "user_id", "user", "id", "SET NULL"),
    ("alertlog", "extension_id", "extension", "id", "CASCADE"),
]


def _name(table: str, column: str) -> str:
    return f"{table}_{column}_fkey"


def upgrade() -> None:
    for table, column, ref_table, ref_col, ondelete in _FKS:
        name = _name(table, column)
        op.drop_constraint(name, table, type_="foreignkey")
        op.create_foreign_key(name, table, ref_table, [column], [ref_col], ondelete=ondelete)


def downgrade() -> None:
    for table, column, ref_table, ref_col, _ondelete in _FKS:
        name = _name(table, column)
        op.drop_constraint(name, table, type_="foreignkey")
        op.create_foreign_key(name, table, ref_table, [column], [ref_col])
