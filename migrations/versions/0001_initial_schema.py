"""Initial database schema for users, documents, permissions, and audit logs.

Revision ID: 0001_initial_schema
Revises: 
Create Date: 2026-10-20 20:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Users table
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_role", "users", ["role"], unique=False)

    # 2. Documents table
    op.create_table(
        "documents",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "owner_id",
            sa.String(length=36),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("category", sa.String(length=100), nullable=False, server_default="General"),
        sa.Column("storage_path", sa.String(length=500), nullable=False),
        sa.Column("file_size", sa.BigInteger(), nullable=False),
        sa.Column("content_type", sa.String(length=120), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("storage_path", name="uq_documents_storage_path"),
    )
    op.create_index("ix_documents_owner_id", "documents", ["owner_id"], unique=False)
    op.create_index("ix_documents_name", "documents", ["name"], unique=False)
    op.create_index("ix_documents_category", "documents", ["category"], unique=False)
    op.create_index("ix_documents_status", "documents", ["status"], unique=False)
    op.create_index("ix_documents_created_at", "documents", ["created_at"], unique=False)

    # 3. Document Permissions table
    op.create_table(
        "document_permissions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "document_id",
            sa.String(length=36),
            sa.ForeignKey("documents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "grantee_id",
            sa.String(length=36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "granted_by_id",
            sa.String(length=36),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("permission_level", sa.String(length=20), nullable=False),
        sa.Column("is_revoked", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint(
            "document_id",
            "grantee_id",
            "permission_level",
            name="uq_doc_grantee_level",
        ),
    )
    op.create_index("ix_doc_perm_document_id", "document_permissions", ["document_id"], unique=False)
    op.create_index("ix_doc_perm_grantee_id", "document_permissions", ["grantee_id"], unique=False)
    op.create_index("ix_doc_perm_is_revoked", "document_permissions", ["is_revoked"], unique=False)
    op.create_index(
        "idx_doc_grantee_active",
        "document_permissions",
        ["document_id", "grantee_id", "is_revoked"],
    )

    # 4. Audit Events table (append-only)
    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "actor_id",
            sa.String(length=36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("actor_email", sa.String(length=255), nullable=True),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("resource_id", sa.String(length=255), nullable=True),
        sa.Column("outcome", sa.String(length=20), nullable=False),
        sa.Column("reason", sa.String(length=500), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=500), nullable=True),
        sa.Column("context_metadata", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_actor_id", "audit_events", ["actor_id"], unique=False)
    op.create_index("ix_audit_actor_email", "audit_events", ["actor_email"], unique=False)
    op.create_index("ix_audit_action", "audit_events", ["action"], unique=False)
    op.create_index("ix_audit_resource_id", "audit_events", ["resource_id"], unique=False)
    op.create_index("ix_audit_outcome", "audit_events", ["outcome"], unique=False)
    op.create_index("ix_audit_created_at", "audit_events", ["created_at"], unique=False)
    op.create_index("idx_audit_action_outcome", "audit_events", ["action", "outcome"], unique=False)
    op.create_index("idx_audit_resource_created", "audit_events", ["resource_id", "created_at"], unique=False)


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("document_permissions")
    op.drop_table("documents")
    op.drop_table("users")
