"""Public document metadata schemas."""

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, field_validator

from app.models import DocumentStatus, PermissionLevel


class SharePermission(str, Enum):
    """Permissions that can currently be granted through the sharing API."""

    VIEW = PermissionLevel.VIEW.value
    DOWNLOAD = PermissionLevel.DOWNLOAD.value


class ShareGrantRequest(BaseModel):
    """Request to grant a supported permission to an existing user."""

    user_id: str
    permission: SharePermission
    expires_at: datetime | None = None

    @field_validator("expires_at")
    @classmethod
    def expiration_must_be_future_and_timezone_aware(
        cls,
        value: datetime | None,
    ) -> datetime | None:
        if value is None:
            return None
        if value.utcoffset() is None:
            raise ValueError("Expiration must include a timezone")
        value = value.astimezone(timezone.utc)
        if value <= datetime.now(timezone.utc):
            raise ValueError("Expiration must be in the future")
        return value


class DocumentShareResponse(BaseModel):
    """Safe public details for a document share."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    document_id: str
    grantee_id: str
    grantee_name: str
    grantee_email: str
    granted_by_id: str
    permission_level: PermissionLevel
    is_revoked: bool
    granted_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None


class DocumentUploadResponse(BaseModel):
    """Metadata returned after a successful upload; never includes a storage path."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    owner_id: str
    name: str
    category: str
    file_size: int
    content_type: str
    status: DocumentStatus
    created_at: datetime


class SharedDocumentResponse(BaseModel):
    """Document metadata and active grants visible to the shared recipient."""

    id: str
    filename: str
    owner_id: str | None
    owner_name: str | None
    owner_email: str | None
    permissions: list[SharePermission]
    file_size: int
    content_type: str
    created_at: datetime
