"""human release approval

Revision ID: e471186cabaf
Revises: 2a2d0fdb184e
Create Date: 2026-11-24 22:02:58.860051
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e471186cabaf'
down_revision: Union[str, None] = '2a2d0fdb184e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "release_files",
        sa.Column("review_status", sa.String(length=16), server_default="pending", nullable=False),
    )
    op.create_index("ix_release_files_review_status", "release_files", ["review_status"])


def downgrade() -> None:
    op.drop_index("ix_release_files_review_status", table_name="release_files")
    op.drop_column("release_files", "review_status")
