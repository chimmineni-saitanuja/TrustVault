"""Safe response schemas for the administrator dashboard."""

from datetime import datetime

from pydantic import BaseModel

from app.models import (
    AuditOutcome,
    DocumentReviewStatus,
    DocumentStatus,
    PermissionLevel,
)
from app.schemas.auth import UserPublicResponse


class AdminActivityResponse(BaseModel):
    id: str
    actor_email: str | None
    action: str
    outcome: AuditOutcome
    created_at: datetime
    document_id: str | None
    document_name: str | None


class PendingDocumentResponse(BaseModel):
    id: str
    name: str
    owner_id: str
    owner_name: str
    owner_email: str
    file_size: int
    content_type: str
    review_status: DocumentReviewStatus
    created_at: datetime


class AdminDocumentResponse(PendingDocumentResponse):
    owner_id: str
    owner_name: str
    owner_email: str
    category: str
    status: DocumentStatus
    rejection_reason: str | None
    reviewed_at: datetime | None


class AdminPermissionResponse(BaseModel):
    id: str
    document_id: str
    document_name: str
    owner_email: str
    grantee_id: str
    grantee_name: str
    grantee_email: str
    granted_by_id: str
    permission_level: PermissionLevel
    is_revoked: bool
    granted_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None


class AdminDashboardResponse(BaseModel):
    users: list[UserPublicResponse]
    activity: list[AdminActivityResponse]
    pending_documents: list[PendingDocumentResponse]
    total_users: int
    total_documents: int
    pending_reviews: int
    approved_documents: int
    rejected_documents: int
