"""Administrator dashboard and document review endpoints."""

import csv
import io
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import FileResponse
from sqlalchemy import func, or_
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.dependencies import require_role
from app.models import (
    AuditAction,
    AuditEvent,
    AuditOutcome,
    Document,
    DocumentPermission,
    DocumentReviewStatus,
    User,
    UserRole,
    get_utc_now,
)
from app.schemas.admin import (
    AdminActivityResponse,
    AdminDashboardResponse,
    AdminDocumentResponse,
    AdminPermissionResponse,
    PendingDocumentResponse,
)
from app.schemas.documents import DocumentReviewRequest, DocumentUploadResponse
from app.schemas.auth import UserPublicResponse
from app.routers.documents import (
    _commit_access_audit,
    _resolve_document_storage_path,
    _verify_document_integrity,
)

logger = logging.getLogger("trustvault.admin")

router = APIRouter()
_AUDIT_LIMIT = 100


def _admin_activity_query(
    db: Session,
    *,
    actor: str | None = None,
    action: str | None = None,
    outcome: AuditOutcome | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
):
    query = db.query(AuditEvent)
    if actor:
        query = query.filter(AuditEvent.actor_email.ilike(f"%{actor}%"))
    if action:
        query = query.filter(AuditEvent.action == action)
    if outcome:
        query = query.filter(AuditEvent.outcome == outcome)
    if date_from:
        query = query.filter(AuditEvent.created_at >= date_from)
    if date_to:
        query = query.filter(AuditEvent.created_at <= date_to)
    return query.order_by(AuditEvent.created_at.desc())


def _activity_responses(db: Session, events: list[AuditEvent]) -> list[AdminActivityResponse]:
    document_ids = {event.resource_id for event in events if event.resource_id}
    documents = (
        {
            document.id: document.name
            for document in db.query(Document).filter(Document.id.in_(document_ids)).all()
        }
        if document_ids
        else {}
    )
    return [
        AdminActivityResponse(
            id=event.id,
            actor_email=event.actor_email,
            action=event.action,
            outcome=event.outcome,
            created_at=event.created_at,
            document_id=event.resource_id if event.resource_id in documents else None,
            document_name=documents.get(event.resource_id),
        )
        for event in events
    ]


def _safe_csv_value(value: str) -> str:
    if value.startswith(("=", "+", "-", "@", "\t", "\r")):
        return f"'{value}"
    return value


@router.get(
    "/dashboard",
    response_model=AdminDashboardResponse,
    summary="Load administrator dashboard",
)
def get_admin_dashboard(
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> AdminDashboardResponse:
    try:
        users = db.query(User).order_by(User.created_at.desc()).all()
        events = db.query(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(_AUDIT_LIMIT).all()
        pending_rows = (
            db.query(Document, User.name, User.email)
            .join(User, User.id == Document.owner_id)
            .filter(Document.review_status == DocumentReviewStatus.PENDING)
            .order_by(Document.created_at.asc())
            .all()
        )
        total_users = db.query(func.count(User.id)).scalar() or 0
        total_documents = db.query(func.count(Document.id)).scalar() or 0
        pending_reviews = (
            db.query(func.count(Document.id))
            .filter(Document.review_status == DocumentReviewStatus.PENDING)
            .scalar()
            or 0
        )
        approved_documents = (
            db.query(func.count(Document.id))
            .filter(Document.review_status == DocumentReviewStatus.APPROVED)
            .scalar()
            or 0
        )
        rejected_documents = (
            db.query(func.count(Document.id))
            .filter(Document.review_status == DocumentReviewStatus.REJECTED)
            .scalar()
            or 0
        )
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Administrator dashboard query failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Administrator dashboard request failed",
        )

    return AdminDashboardResponse(
        users=users,
        activity=_activity_responses(db, events),
        pending_documents=[
            PendingDocumentResponse(
                id=document.id,
                name=document.name,
                owner_id=document.owner_id,
                owner_name=owner_name,
                owner_email=owner_email,
                file_size=document.file_size,
                content_type=document.content_type,
                review_status=document.review_status,
                created_at=document.created_at,
            )
            for document, owner_name, owner_email in pending_rows
        ],
        total_users=total_users,
        total_documents=total_documents,
        pending_reviews=pending_reviews,
        approved_documents=approved_documents,
        rejected_documents=rejected_documents,
    )


@router.get("/documents", response_model=list[AdminDocumentResponse])
def list_all_documents(
    owner: str | None = None,
    owner_id: str | None = None,
    filename: str | None = None,
    review_status: DocumentReviewStatus | None = None,
    upload_from: datetime | None = None,
    upload_to: datetime | None = None,
    _current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> list[AdminDocumentResponse]:
    """Search all document metadata. File access remains restricted to preview."""
    try:
        query = db.query(Document, User.name, User.email).join(User, User.id == Document.owner_id)
        if owner:
            owner_pattern = f"%{owner}%"
            query = query.filter(
                or_(
                    User.id.ilike(owner_pattern),
                    User.name.ilike(owner_pattern),
                    User.email.ilike(owner_pattern),
                )
            )
        if owner_id:
            query = query.filter(Document.owner_id == owner_id)
        if filename:
            query = query.filter(Document.name.ilike(f"%{filename}%"))
        if review_status:
            query = query.filter(Document.review_status == review_status)
        if upload_from:
            query = query.filter(Document.created_at >= upload_from)
        if upload_to:
            query = query.filter(Document.created_at <= upload_to)
        rows = query.order_by(Document.created_at.desc()).all()
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Administrator document search failed")
        raise HTTPException(status_code=500, detail="Administrator document request failed")

    return [
        AdminDocumentResponse(
            id=document.id,
            name=document.name,
            owner_id=document.owner_id,
            owner_name=owner_name,
            owner_email=owner_email,
            file_size=document.file_size,
            content_type=document.content_type,
            review_status=document.review_status,
            created_at=document.created_at,
            category=document.category,
            status=document.status,
            rejection_reason=document.rejection_reason,
            reviewed_at=document.reviewed_at,
        )
        for document, owner_name, owner_email in rows
    ]


@router.get("/audit", response_model=list[AdminActivityResponse])
def list_admin_audit(
    actor: str | None = None,
    action: str | None = None,
    outcome: AuditOutcome | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    _current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> list[AdminActivityResponse]:
    """Return safe audit fields only; no request details, secrets, or credentials."""
    try:
        events = _admin_activity_query(
            db,
            actor=actor,
            action=action,
            outcome=outcome,
            date_from=date_from,
            date_to=date_to,
        ).limit(_AUDIT_LIMIT).all()
        return _activity_responses(db, events)
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Administrator audit query failed")
        raise HTTPException(status_code=500, detail="Administrator audit request failed")


@router.get("/permissions", response_model=list[AdminPermissionResponse])
def list_admin_permissions(
    _current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> list[AdminPermissionResponse]:
    try:
        rows = (
            db.query(DocumentPermission, Document, User, User.name, User.email)
            .join(Document, Document.id == DocumentPermission.document_id)
            .join(User, User.id == DocumentPermission.grantee_id)
            .order_by(DocumentPermission.granted_at.desc())
            .all()
        )
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Administrator permission listing failed")
        raise HTTPException(status_code=500, detail="Administrator permission request failed")

    return [
        AdminPermissionResponse(
            id=permission.id,
            document_id=document.id,
            document_name=document.name,
            owner_email=document.owner.email,
            grantee_id=permission.grantee_id,
            grantee_name=grantee_name,
            grantee_email=grantee_email,
            granted_by_id=permission.granted_by_id,
            permission_level=permission.permission_level,
            is_revoked=permission.is_revoked,
            granted_at=permission.granted_at,
            expires_at=permission.expires_at,
            revoked_at=permission.revoked_at,
        )
        for permission, document, _grantee, grantee_name, grantee_email in rows
    ]


@router.delete("/permissions/{permission_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_admin_permission(
    permission_id: str,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> None:
    try:
        permission = (
            db.query(DocumentPermission)
            .filter(DocumentPermission.id == permission_id)
            .with_for_update()
            .first()
        )
        if permission is None:
            raise HTTPException(status_code=404, detail="Permission grant not found")
        if permission.is_revoked:
            raise HTTPException(status_code=409, detail="Permission grant is already revoked")
        permission.is_revoked = True
        permission.revoked_at = get_utc_now()
        db.add(
            AuditEvent(
                actor_id=current_user.id,
                actor_email=current_user.email,
                action=AuditAction.PERMISSION_REVOKE,
                resource_id=permission.document_id,
                outcome=AuditOutcome.SUCCESS,
                context_metadata={
                    "share_id": permission.id,
                    "grantee_id": permission.grantee_id,
                    "permission": permission.permission_level.value,
                },
            )
        )
        db.commit()
    except HTTPException:
        raise
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Administrator permission revocation failed")
        raise HTTPException(status_code=500, detail="Administrator permission request failed")


def _set_user_active(
    user_id: str,
    active: bool,
    current_user: User,
    db: Session,
) -> UserPublicResponse:
    try:
        if not active:
            (
                db.query(User)
                .filter(User.role == UserRole.ADMIN, User.is_active.is_(True))
                .order_by(User.id)
                .with_for_update()
                .all()
            )
        target = db.query(User).filter(User.id == user_id).with_for_update().first()
        if target is None:
            raise HTTPException(status_code=404, detail="User not found")
        if target.is_active == active:
            raise HTTPException(status_code=409, detail="User account already has that status")
        if not active and target.role == UserRole.ADMIN:
            active_admin_count = (
                db.query(func.count(User.id))
                .filter(User.role == UserRole.ADMIN, User.is_active.is_(True))
                .scalar()
                or 0
            )
            if active_admin_count <= 1:
                raise HTTPException(status_code=409, detail="The last active administrator cannot be deactivated")

        target.is_active = active
        db.add(
            AuditEvent(
                actor_id=current_user.id,
                actor_email=current_user.email,
                action=AuditAction.USER_REACTIVATE if active else AuditAction.USER_DEACTIVATE,
                resource_id=target.id,
                outcome=AuditOutcome.SUCCESS,
                context_metadata={"target_email": target.email},
            )
        )
        db.commit()
        db.refresh(target)
        return UserPublicResponse.model_validate(target)
    except HTTPException:
        raise
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Administrator account status update failed")
        raise HTTPException(status_code=500, detail="Administrator user request failed")


@router.post("/users/{user_id}/deactivate", response_model=UserPublicResponse)
def deactivate_user(
    user_id: str,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> UserPublicResponse:
    return _set_user_active(user_id, False, current_user, db)


@router.post("/users/{user_id}/reactivate", response_model=UserPublicResponse)
def reactivate_user(
    user_id: str,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> UserPublicResponse:
    return _set_user_active(user_id, True, current_user, db)


@router.get("/reports/export")
def export_admin_report(
    actor: str | None = None,
    action: str | None = None,
    outcome: AuditOutcome | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    _current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> Response:
    """Export filtered audit/review history as a safe CSV attachment."""
    try:
        events = _admin_activity_query(
            db,
            actor=actor,
            action=action,
            outcome=outcome,
            date_from=date_from,
            date_to=date_to,
        ).all()
        activities = _activity_responses(db, events)
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Administrator report export failed")
        raise HTTPException(status_code=500, detail="Administrator report request failed")

    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["event_id", "actor", "action", "outcome", "created_at", "document_id", "document_name"])
    for event in activities:
        writer.writerow([
            event.id,
            _safe_csv_value(event.actor_email or ""),
            _safe_csv_value(event.action),
            event.outcome.value,
            event.created_at.isoformat(),
            event.document_id or "",
            _safe_csv_value(event.document_name or ""),
        ])
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="trustvault-admin-report.csv"'},
    )


def _review_pending_document(
    document_id: str,
    current_user: User,
    db: Session,
    review_status: DocumentReviewStatus,
    rejection_reason: str | None = None,
) -> DocumentUploadResponse:
    try:
        document = (
            db.query(Document)
            .filter(Document.id == document_id)
            .with_for_update()
            .first()
        )
        if document is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Document not found",
            )
        if document.review_status != DocumentReviewStatus.PENDING:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Document is no longer awaiting review",
            )

        document.review_status = review_status
        document.rejection_reason = rejection_reason
        document.reviewed_by_id = current_user.id
        document.reviewed_at = get_utc_now()
        db.add(
            AuditEvent(
                actor_id=current_user.id,
                actor_email=current_user.email,
                action=(
                    AuditAction.DOCUMENT_APPROVE
                    if review_status == DocumentReviewStatus.APPROVED
                    else AuditAction.DOCUMENT_REJECT
                ),
                resource_id=document.id,
                outcome=AuditOutcome.SUCCESS,
                context_metadata={"review_status": review_status.value},
            )
        )
        db.commit()
        db.refresh(document)
    except HTTPException:
        raise
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Document review persistence failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Document review could not be saved",
        )

    return DocumentUploadResponse.model_validate(document)


@router.get(
    "/documents/{document_id}/preview",
    response_class=FileResponse,
    summary="Preview a document for administrator review",
)
def preview_pending_document(
    document_id: str,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> FileResponse:
    try:
        document = db.query(Document).filter(Document.id == document_id).first()
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Pending document review lookup failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Document review request failed",
        )
    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    file_path = _resolve_document_storage_path(document.storage_path)
    if file_path is None:
        _commit_access_audit(
            db,
            AuditEvent(
                actor_id=current_user.id,
                actor_email=current_user.email,
                action=AuditAction.DOCUMENT_READ,
                resource_id=document.id,
                outcome=AuditOutcome.ERROR,
                reason="Pending document file is unavailable",
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document file not found",
        )

    _verify_document_integrity(
        document,
        file_path,
        current_user,
        db,
        AuditAction.DOCUMENT_READ,
    )
    _commit_access_audit(
        db,
        AuditEvent(
            actor_id=current_user.id,
            actor_email=current_user.email,
            action=AuditAction.DOCUMENT_READ,
            resource_id=document.id,
            outcome=AuditOutcome.SUCCESS,
            context_metadata={"operation": "admin_review_preview"},
        ),
    )
    return FileResponse(
        path=file_path,
        media_type=document.content_type,
        filename=document.name,
        content_disposition_type="inline",
        headers={"X-Content-Type-Options": "nosniff"},
    )


@router.post(
    "/documents/{document_id}/approve",
    response_model=DocumentUploadResponse,
    summary="Approve an uploaded document",
)
def approve_document(
    document_id: str,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> DocumentUploadResponse:
    return _review_pending_document(
        document_id,
        current_user,
        db,
        DocumentReviewStatus.APPROVED,
    )


@router.post(
    "/documents/{document_id}/reject",
    response_model=DocumentUploadResponse,
    summary="Reject an uploaded document",
)
def reject_document(
    document_id: str,
    request_body: DocumentReviewRequest,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> DocumentUploadResponse:
    return _review_pending_document(
        document_id,
        current_user,
        db,
        DocumentReviewStatus.REJECTED,
        request_body.reason,
    )
