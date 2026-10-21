"""SQLAlchemy database models for TrustVault.

Covers Users, Documents, Document Permissions, and append-only Audit Events.
Includes strict enum definitions, foreign key rules, and immutability guards.
"""

from datetime import datetime, timezone
import enum
import uuid
from typing import Any, Dict, Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum as SQLEnum,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    event,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.database import Base


def get_utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


class UserRole(str, enum.Enum):
    """User authorization roles."""
    ADMIN = "admin"
    OWNER = "owner"
    VIEWER = "viewer"


class PermissionLevel(str, enum.Enum):
    """Document permission levels."""
    VIEW = "view"
    DOWNLOAD = "download"
    READ = "read"
    EDIT = "edit"


class DocumentStatus(str, enum.Enum):
    """Document lifecycle states."""
    ACTIVE = "active"
    DELETED = "deleted"
    ARCHIVED = "archived"


class AuditAction(str, enum.Enum):
    """Audit action event types."""
    # Authentication events
    USER_REGISTER = "user.register"
    LOGIN_SUCCESS = "auth.login_success"
    LOGIN_FAILED = "auth.login_failed"
    LOGOUT = "auth.logout"

    # Document operations
    DOCUMENT_UPLOAD = "document.upload"
    DOCUMENT_READ = "document.read"
    DOCUMENT_DOWNLOAD = "document.download"
    DOCUMENT_EDIT = "document.edit"
    DOCUMENT_DELETE = "document.delete"

    # Permission changes
    PERMISSION_GRANT = "permission.grant"
    PERMISSION_REVOKE = "permission.revoke"

    # Security violations and denied attempts
    ACCESS_DENIED = "security.access_denied"
    UNAUTHORIZED_ACCESS_ATTEMPT = "security.unauthorized_attempt"


class AuditOutcome(str, enum.Enum):
    """Outcome of audited actions."""
    SUCCESS = "success"
    DENIED = "denied"
    ERROR = "error"


class ReadOnlyAuditLogError(Exception):
    """Raised when an attempt is made to update or delete an audit record."""
    pass


class User(Base):
    """User account entity with role-based access level."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
    )
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        SQLEnum(UserRole, native_enum=False, length=20),
        default=UserRole.VIEWER,
        nullable=False,
        index=True,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=get_utc_now,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=get_utc_now,
        onupdate=get_utc_now,
        nullable=False,
    )

    # Relationships
    owned_documents = relationship(
        "Document",
        back_populates="owner",
        cascade="all, delete-orphan",
        foreign_keys="Document.owner_id",
    )
    granted_permissions = relationship(
        "DocumentPermission",
        back_populates="grantee",
        foreign_keys="DocumentPermission.grantee_id",
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email} role={self.role}>"


class Document(Base):
    """Document metadata entity storing reference to private file storage."""

    __tablename__ = "documents"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    owner_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    category: Mapped[str] = mapped_column(
        String(100),
        default="General",
        nullable=False,
        index=True,
    )
    storage_path: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        unique=True,
    )
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    content_type: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[DocumentStatus] = mapped_column(
        SQLEnum(DocumentStatus, native_enum=False, length=20),
        default=DocumentStatus.ACTIVE,
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=get_utc_now,
        nullable=False,
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=get_utc_now,
        onupdate=get_utc_now,
        nullable=False,
    )

    # Relationships
    owner = relationship("User", back_populates="owned_documents", foreign_keys=[owner_id])
    permissions = relationship(
        "DocumentPermission",
        back_populates="document",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Document id={self.id} name={self.name} owner_id={self.owner_id} status={self.status}>"


class DocumentPermission(Base):
    """Explicit per-user permissions granted on individual documents."""

    __tablename__ = "document_permissions"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    document_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("documents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    grantee_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    granted_by_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    permission_level: Mapped[PermissionLevel] = mapped_column(
        SQLEnum(PermissionLevel, native_enum=False, length=20),
        nullable=False,
    )
    is_revoked: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        index=True,
    )
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=get_utc_now,
        nullable=False,
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    document = relationship("Document", back_populates="permissions")
    grantee = relationship("User", foreign_keys=[grantee_id], back_populates="granted_permissions")
    granted_by = relationship("User", foreign_keys=[granted_by_id])

    __table_args__ = (
        UniqueConstraint(
            "document_id",
            "grantee_id",
            "permission_level",
            name="uq_doc_grantee_level",
        ),
        Index("idx_doc_grantee_active", "document_id", "grantee_id", "is_revoked"),
    )

    def __repr__(self) -> str:
        return (
            f"<DocumentPermission id={self.id} doc={self.document_id} "
            f"grantee={self.grantee_id} level={self.permission_level} revoked={self.is_revoked}>"
        )


class AuditEvent(Base):
    """Append-only audit trail recording access, operations, and denied attempts.
    
    Security Guarantee:
    - Never hard-cascaded on document deletion (resource_id is a plain string identifier).
    - Actor ID is nullable and SET NULL on user deletion, while actor_email persists.
    - Application-level mutations and deletions are blocked by SQLAlchemy event listeners.
    """

    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    # Actor information: nullable for unauthenticated or deleted users
    actor_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    actor_email: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )
    action: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    # Resource identifier stored as string so record survives document deletion
    resource_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )
    outcome: Mapped[AuditOutcome] = mapped_column(
        SQLEnum(AuditOutcome, native_enum=False, length=20),
        nullable=False,
        index=True,
    )
    reason: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
    )
    ip_address: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    user_agent: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
    )
    context_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=get_utc_now,
        nullable=False,
        index=True,
    )

    __table_args__ = (
        Index("idx_audit_action_outcome", "action", "outcome"),
        Index("idx_audit_resource_created", "resource_id", "created_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<AuditEvent id={self.id} action={self.action} "
            f"outcome={self.outcome} actor={self.actor_email}>"
        )


# Immutability guards for AuditEvent
@event.listens_for(AuditEvent, "before_update")
def prevent_audit_update(mapper, connection, target):
    """Enforce append-only integrity by blocking updates to audit records."""
    raise ReadOnlyAuditLogError("Audit log records are append-only and cannot be modified.")


@event.listens_for(AuditEvent, "before_delete")
def prevent_audit_delete(mapper, connection, target):
    """Enforce append-only integrity by blocking deletion of audit records."""
    raise ReadOnlyAuditLogError("Audit log records are append-only and cannot be deleted.")
