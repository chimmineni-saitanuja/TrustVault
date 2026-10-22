"""Authenticated, actor-scoped activity history."""

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import or_
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user
from app.models import (
    AuditAction,
    AuditEvent,
    Document,
    DocumentPermission,
    PermissionLevel,
    User,
    get_utc_now,
)
from app.schemas.activity import ActivityEventResponse

logger = logging.getLogger("trustvault.activity")

router = APIRouter()
_ACTIVITY_LIMIT = 100
_SHARE_ACTIONS = {
    AuditAction.PERMISSION_GRANT.value,
    AuditAction.PERMISSION_REVOKE.value,
}


@router.get(
    "/",
    response_model=list[ActivityEventResponse],
    summary="List the authenticated user's recent activity",
)
def list_activity(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[ActivityEventResponse]:
    """Return recent events performed by this user with currently authorized labels."""
    try:
        events = (
            db.query(AuditEvent)
            .filter(AuditEvent.actor_id == current_user.id)
            .order_by(AuditEvent.created_at.desc())
            .limit(_ACTIVITY_LIMIT)
            .all()
        )
        accessible_documents = (
            db.query(Document.id, Document.name)
            .filter(
                or_(
                    Document.owner_id == current_user.id,
                    Document.id.in_(
                        db.query(DocumentPermission.document_id).filter(
                            DocumentPermission.grantee_id == current_user.id,
                            DocumentPermission.is_revoked.is_(False),
                            DocumentPermission.permission_level.in_(
                                [PermissionLevel.VIEW, PermissionLevel.DOWNLOAD]
                            ),
                            or_(
                                DocumentPermission.expires_at.is_(None),
                                DocumentPermission.expires_at > get_utc_now(),
                            ),
                        )
                    ),
                )
            )
            .all()
        )
        document_names = {document_id: name for document_id, name in accessible_documents}

        related_user_ids = {
            event.context_metadata.get("grantee_id")
            for event in events
            if event.action in _SHARE_ACTIONS
            and event.resource_id in document_names
            and isinstance(event.context_metadata, dict)
            and isinstance(event.context_metadata.get("grantee_id"), str)
        }
        related_users = (
            {
                user.id: user
                for user in db.query(User).filter(User.id.in_(related_user_ids)).all()
            }
            if related_user_ids
            else {}
        )
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Activity listing failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Activity request failed",
        )

    response = []
    for event in events:
        document_id = event.resource_id if event.resource_id in document_names else None
        related_user_id = None
        if (
            event.action in _SHARE_ACTIONS
            and document_id is not None
            and isinstance(event.context_metadata, dict)
        ):
            candidate_id = event.context_metadata.get("grantee_id")
            if isinstance(candidate_id, str):
                related_user_id = candidate_id

        related_user = related_users.get(related_user_id)
        response.append(
            ActivityEventResponse(
                id=event.id,
                action=event.action,
                outcome=event.outcome,
                created_at=event.created_at,
                document_id=document_id,
                document_name=document_names.get(document_id) if document_id else None,
                related_user_name=related_user.name if related_user else None,
                related_user_email=related_user.email if related_user else None,
            )
        )
    return response
