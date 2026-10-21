"""Authenticated document upload endpoint."""

import codecs
import logging
from pathlib import Path
import uuid

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.dependencies import get_current_user
from app.models import (
    AuditAction,
    AuditEvent,
    AuditOutcome,
    Document,
    DocumentPermission,
    PermissionLevel,
    User,
    UserRole,
    get_utc_now,
)
from app.schemas.documents import (
    DocumentShareResponse,
    DocumentUploadResponse,
    ShareGrantRequest,
)

logger = logging.getLogger("trustvault.documents")

router = APIRouter()

_CHUNK_SIZE = 64 * 1024
_ALLOWED_TYPES = {
    ".pdf": ("application/pdf", b"%PDF-"),
    ".png": ("image/png", b"\x89PNG\r\n\x1a\n"),
    ".jpg": ("image/jpeg", b"\xff\xd8\xff"),
    ".jpeg": ("image/jpeg", b"\xff\xd8\xff"),
    ".txt": ("text/plain", None),
}


def _remove_partial_file(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        logger.exception("Could not remove a partial document upload")


def _commit_access_audit(db: Session, audit: AuditEvent) -> None:
    try:
        db.add(audit)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Document access audit persistence failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Document request failed",
        )


def _get_shareable_document(
    document_id: str,
    current_user: User,
    db: Session,
) -> Document:
    try:
        document = db.query(Document).filter(Document.id == document_id).first()
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Document sharing lookup failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Document request failed",
        )

    if document is None or (
        document.owner_id != current_user.id and current_user.role != UserRole.ADMIN
    ):
        _commit_access_audit(
            db,
            AuditEvent(
                actor_id=current_user.id,
                actor_email=current_user.email,
                action=AuditAction.ACCESS_DENIED,
                resource_id=document_id[:255],
                outcome=AuditOutcome.DENIED,
                reason="Document not found or user cannot manage shares",
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )
    return document


def _share_response(share: DocumentPermission) -> DocumentShareResponse:
    return DocumentShareResponse(
        id=share.id,
        document_id=share.document_id,
        grantee_id=share.grantee_id,
        grantee_name=share.grantee.name,
        grantee_email=share.grantee.email,
        granted_by_id=share.granted_by_id,
        permission_level=share.permission_level,
        is_revoked=share.is_revoked,
        granted_at=share.granted_at,
        revoked_at=share.revoked_at,
    )


@router.post(
    "/{document_id}/shares",
    response_model=DocumentShareResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Grant document access",
)
def grant_document_share(
    document_id: str,
    request_body: ShareGrantRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DocumentShareResponse:
    """Grant view or download permission to an active user."""
    document = _get_shareable_document(document_id, current_user, db)
    if request_body.user_id == document.owner_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot grant a share to the document owner",
        )

    try:
        grantee = (
            db.query(User)
            .filter(User.id == request_body.user_id, User.is_active.is_(True))
            .first()
        )
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Share recipient lookup failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Share request failed",
        )
    if grantee is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Active user not found",
        )

    permission_level = PermissionLevel(request_body.permission.value)
    try:
        share = (
            db.query(DocumentPermission)
            .filter(
                DocumentPermission.document_id == document.id,
                DocumentPermission.grantee_id == grantee.id,
                DocumentPermission.permission_level == permission_level,
            )
            .first()
        )
        if share is not None and not share.is_revoked:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This permission has already been granted",
            )

        if share is None:
            share = DocumentPermission(
                document_id=document.id,
                grantee_id=grantee.id,
                granted_by_id=current_user.id,
                permission_level=permission_level,
                is_revoked=False,
                grantee=grantee,
            )
            db.add(share)
        else:
            share.granted_by_id = current_user.id
            share.is_revoked = False
            share.granted_at = get_utc_now()
            share.revoked_at = None
            share.grantee = grantee

        audit = AuditEvent(
            actor_id=current_user.id,
            actor_email=current_user.email,
            action=AuditAction.PERMISSION_GRANT,
            resource_id=document.id,
            outcome=AuditOutcome.SUCCESS,
            context_metadata={
                "grantee_id": grantee.id,
                "permission": permission_level.value,
            },
        )
        db.add(audit)
        db.commit()
    except HTTPException:
        raise
    except IntegrityError:
        db.rollback()
        try:
            duplicate = (
                db.query(DocumentPermission)
                .filter(
                    DocumentPermission.document_id == document.id,
                    DocumentPermission.grantee_id == request_body.user_id,
                    DocumentPermission.permission_level == permission_level,
                    DocumentPermission.is_revoked.is_(False),
                )
                .first()
            )
        except SQLAlchemyError:
            db.rollback()
            logger.exception("Share grant conflict lookup failed")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Share request failed",
            )
        if duplicate is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This permission has already been granted",
            )
        logger.exception("Share grant persistence failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Share request failed",
        )
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Share grant persistence failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Share request failed",
        )

    return _share_response(share)


@router.get(
    "/{document_id}/shares",
    response_model=list[DocumentShareResponse],
    summary="List document shares",
)
def list_document_shares(
    document_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[DocumentShareResponse]:
    """List document shares for the owner or an admin."""
    document = _get_shareable_document(document_id, current_user, db)
    try:
        shares = (
            db.query(DocumentPermission)
            .filter(DocumentPermission.document_id == document.id)
            .order_by(DocumentPermission.granted_at.desc())
            .all()
        )
        response = [_share_response(share) for share in shares]
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Document share listing failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Share request failed",
        )

    _commit_access_audit(
        db,
        AuditEvent(
            actor_id=current_user.id,
            actor_email=current_user.email,
            action=AuditAction.DOCUMENT_READ,
            resource_id=document.id,
            outcome=AuditOutcome.SUCCESS,
            context_metadata={"operation": "list_shares", "share_count": len(shares)},
        ),
    )
    return response


@router.delete(
    "/{document_id}/shares/{share_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke document access",
)
def revoke_document_share(
    document_id: str,
    share_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    """Revoke an existing share for the owner or an admin."""
    document = _get_shareable_document(document_id, current_user, db)
    try:
        share = (
            db.query(DocumentPermission)
            .filter(
                DocumentPermission.id == share_id,
                DocumentPermission.document_id == document.id,
            )
            .first()
        )
        if share is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Share not found")
        if share.is_revoked:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Share has already been revoked",
            )

        share.is_revoked = True
        share.revoked_at = get_utc_now()
        audit = AuditEvent(
            actor_id=current_user.id,
            actor_email=current_user.email,
            action=AuditAction.PERMISSION_REVOKE,
            resource_id=document.id,
            outcome=AuditOutcome.SUCCESS,
            context_metadata={
                "share_id": share.id,
                "grantee_id": share.grantee_id,
                "permission": share.permission_level.value,
            },
        )
        db.add(audit)
        db.commit()
    except HTTPException:
        raise
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Share revoke persistence failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Share request failed",
        )
    return None


@router.get(
    "/",
    response_model=list[DocumentUploadResponse],
    summary="List the current user's documents",
)
def list_documents(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[DocumentUploadResponse]:
    """List only documents owned by the authenticated user."""
    try:
        documents = (
            db.query(Document)
            .filter(Document.owner_id == current_user.id)
            .order_by(Document.created_at.desc())
            .all()
        )
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Document listing failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Document request failed",
        )

    _commit_access_audit(
        db,
        AuditEvent(
            actor_id=current_user.id,
            actor_email=current_user.email,
            action=AuditAction.DOCUMENT_READ,
            outcome=AuditOutcome.SUCCESS,
            context_metadata={"operation": "list", "document_count": len(documents)},
        ),
    )
    return [DocumentUploadResponse.model_validate(document) for document in documents]


@router.get(
    "/{document_id}",
    response_model=DocumentUploadResponse,
    summary="View owned document metadata",
)
def get_document(
    document_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DocumentUploadResponse:
    """Return document metadata only when it belongs to the authenticated user."""
    try:
        document = (
            db.query(Document)
            .filter(
                Document.id == document_id,
                Document.owner_id == current_user.id,
            )
            .first()
        )
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Document details lookup failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Document request failed",
        )

    if document is None:
        _commit_access_audit(
            db,
            AuditEvent(
                actor_id=current_user.id,
                actor_email=current_user.email,
                action=AuditAction.ACCESS_DENIED,
                resource_id=document_id[:255],
                outcome=AuditOutcome.DENIED,
                reason="Document not found or not owned by user",
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    _commit_access_audit(
        db,
        AuditEvent(
            actor_id=current_user.id,
            actor_email=current_user.email,
            action=AuditAction.DOCUMENT_READ,
            resource_id=document.id,
            outcome=AuditOutcome.SUCCESS,
        ),
    )
    return DocumentUploadResponse.model_validate(document)


@router.post(
    "/upload",
    response_model=DocumentUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload a document",
    description=(
        "Stores a validated file in private local storage and records its metadata. "
        "The authenticated user becomes its owner. Sharing and downloading are not provided."
    ),
)
async def upload_document(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DocumentUploadResponse:
    filename = file.filename
    if (
        not filename
        or len(filename) > 255
        or filename in {".", ".."}
        or "/" in filename
        or "\\" in filename
        or any(ord(character) < 32 or ord(character) == 127 for character in filename)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file name",
        )

    extension = Path(filename).suffix.lower()
    allowed_type = _ALLOWED_TYPES.get(extension)
    content_type = (file.content_type or "").split(";", maxsplit=1)[0].strip().lower()
    if allowed_type is None or content_type != allowed_type[0]:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Unsupported file type",
        )

    document_id = str(uuid.uuid4())
    storage_name = f"{uuid.UUID(document_id).hex}{extension}"
    storage_directory = Path(settings.STORAGE_DIR)
    storage_path = storage_directory / storage_name
    size = 0
    first_chunk = True
    text_decoder = codecs.getincrementaldecoder("utf-8")() if extension == ".txt" else None

    try:
        storage_directory.mkdir(parents=True, exist_ok=True)
        with storage_path.open("xb") as destination:
            while chunk := await file.read(_CHUNK_SIZE):
                size += len(chunk)
                if size > settings.MAX_UPLOAD_SIZE_BYTES:
                    raise HTTPException(
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                        detail="File exceeds the maximum upload size",
                    )

                if first_chunk:
                    signature = allowed_type[1]
                    if signature is not None and not chunk.startswith(signature):
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="File contents do not match the declared file type",
                        )
                    first_chunk = False

                if text_decoder is not None:
                    text_decoder.decode(chunk, final=False)
                destination.write(chunk)

            if size == 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="File must not be empty",
                )
            if text_decoder is not None:
                text_decoder.decode(b"", final=True)
    except HTTPException:
        _remove_partial_file(storage_path)
        raise
    except UnicodeDecodeError:
        _remove_partial_file(storage_path)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Text files must contain valid UTF-8",
        )
    except OSError:
        _remove_partial_file(storage_path)
        logger.exception("Document upload storage failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Document upload failed",
        )
    finally:
        await file.close()

    document = Document(
        id=document_id,
        owner_id=current_user.id,
        name=filename,
        storage_path=storage_name,
        file_size=size,
        content_type=content_type,
    )
    audit = AuditEvent(
        actor_id=current_user.id,
        actor_email=current_user.email,
        action=AuditAction.DOCUMENT_UPLOAD,
        resource_id=document_id,
        outcome=AuditOutcome.SUCCESS,
        context_metadata={
            "name": filename,
            "file_size": size,
            "content_type": content_type,
        },
    )

    try:
        db.add_all([document, audit])
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        _remove_partial_file(storage_path)
        logger.exception("Document metadata or audit persistence failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Document upload failed",
        )

    return DocumentUploadResponse.model_validate(document)
