"""Add administrator document review state.

Revision ID: 0004_document_review
Revises: 0003_document_sha256
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0004_document_review"
down_revision: Union[str, None] = "0003_document_sha256"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "documents",
        sa.Column(
            "review_status",
            sa.String(length=20),
            nullable=False,
            server_default="APPROVED",
        ),
    )
    op.add_column(
        "documents",
        sa.Column("rejection_reason", sa.String(length=500), nullable=True),
    )
    op.add_column(
        "documents",
        sa.Column("reviewed_by_id", sa.String(length=36), nullable=True),
    )
    op.add_column(
        "documents",
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
    )
    with op.batch_alter_table("documents") as batch_op:
        batch_op.create_foreign_key(
            "fk_documents_reviewed_by_id_users",
            "users",
            ["reviewed_by_id"],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    with op.batch_alter_table("documents") as batch_op:
        batch_op.drop_constraint(
            "fk_documents_reviewed_by_id_users",
            type_="foreignkey",
        )
    op.drop_column("documents", "reviewed_at")
    op.drop_column("documents", "reviewed_by_id")
    op.drop_column("documents", "rejection_reason")
    op.drop_column("documents", "review_status")
