"""add index for the dashboard's latest-FetchLog-per-extension lookup

The dashboard resolves each extension's most recent FetchLog on every render
(routes/ui.py:_latest_fetch_logs). FetchLog previously carried only the
single-column extension_id index, so the latest-per-extension query re-sorted
each extension's whole history — a multi-second landing page once a large
watchlist accumulates months of logs (#284). Sibling InstallCountHistory
already carries the analogous composite for its latest-N lookup.

Revision ID: c9d0e1f2a3b4
Revises: 39d4509e2a67
Create Date: 2026-07-19 23:50:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c9d0e1f2a3b4"
down_revision: Union[str, None] = "39d4509e2a67"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index(
        "ix_fetchlog_extension_fetched_id",
        "fetchlog",
        ["extension_id", sa.text("fetched_at DESC"), sa.text("id DESC")],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_fetchlog_extension_fetched_id", table_name="fetchlog")
