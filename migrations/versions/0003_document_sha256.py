"""Persist optional SHA-256 digests for stored documents.

Revision ID: 0003_document_sha256
Revises: 0002_document_permission_expiration
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0003_document_sha256"
down_revision: Union[str, None] = "0002_document_permission_expiration"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "documents",
        sa.Column("sha256", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("documents", "sha256")
