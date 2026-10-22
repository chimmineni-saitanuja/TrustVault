"""Authenticated document upload endpoint."""

import codecs
import hashlib
import logging
from pathlib import Path
import uuid

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy import or_
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
    SharedDocumentResponse,
    ShareGrantRequest,
    SharePermission,
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


def _active_permission_conditions():
    now = get_utc_now()
    return (
        DocumentPermission.is_revoked.is_(False),
        or_(
            DocumentPermission.expires_at.is_(None),
            DocumentPermission.expires_at > now,
        ),
    )


def _is_active_permission(permission: DocumentPermission, now=None) -> bool:
    if permission.is_revoked:
        return False
    if permission.expires_at is None:
        return True
    current_time = now or get_utc_now()
    expiration = permission.expires_at
    if expiration.tzinfo is None:
        expiration = expiration.replace(tzinfo=current_time.tzinfo)
    return expiration > current_time


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


def _resolve_document_storage_path(storage_path: str) -> Path | None:
    """Resolve a stored relative path only when it remains inside private storage."""
    try:
        storage_root = Path(settings.STORAGE_DIR).resolve(strict=True)
        resolved_path = (storage_root / storage_path).resolve(strict=True)
        resolved_path.relative_to(storage_root)
    except (OSError, RuntimeError, ValueError):
        return None

    return resolved_path if resolved_path.is_file() else None


def _verify_document_integrity(
    document: Document,
    file_path: Path,
    current_user: User,
    db: Session,
    action: AuditAction,
) -> None:
    digest = hashlib.sha256()
    try:
        with file_path.open("rb") as source:
            while chunk := source.read(_CHUNK_SIZE):
                digest.update(chunk)
    except OSError:
        _commit_access_audit(
            db,
            AuditEvent(
                actor_id=current_user.id,
                actor_email=current_user.email,
                action=action,
                resource_id=document.id,
                outcome=AuditOutcome.ERROR,
                reason="Stored document could not be verified",
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Document integrity verification failed",
        )

    calculated_sha256 = digest.hexdigest()
    if document.sha256 is None:
        document.sha256 = calculated_sha256
        try:
            db.commit()
        except SQLAlchemyError:
            db.rollback()
            logger.exception("Legacy document integrity baseline persistence failed")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Document request failed",
            )
    elif document.sha256 != calculated_sha256:
        _commit_access_audit(
            db,
            AuditEvent(
                actor_id=current_user.id,
                actor_email=current_user.email,
                action=action,
                resource_id=document.id,
                outcome=AuditOutcome.ERROR,
                reason="Stored document integrity verification failed",
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Document integrity verification failed",
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
        expires_at=share.expires_at,
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
        if share is not None and _is_active_permission(share):
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
                expires_at=request_body.expires_at,
                grantee=grantee,
            )
            db.add(share)
        else:
            share.granted_by_id = current_user.id
            share.is_revoked = False
            share.granted_at = get_utc_now()
            share.expires_at = request_body.expires_at
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
                "expires_at": (
                    request_body.expires_at.isoformat()
                    if request_body.expires_at
                    else None
                ),
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
                    *_active_permission_conditions(),
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
    "/{document_id}/preview",
    response_class=FileResponse,
    summary="Preview an authorized document",
)
def preview_document(
    document_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> FileResponse:
    """Serve an owned or actively shared document inline for viewing."""
    try:
        document = db.query(Document).filter(Document.id == document_id).first()
        if document is None:
            has_view_access = False
        elif document.owner_id == current_user.id:
            has_view_access = True
        else:
            has_view_access = (
                db.query(DocumentPermission)
                .filter(
                    DocumentPermission.document_id == document.id,
                    DocumentPermission.grantee_id == current_user.id,
                    DocumentPermission.permission_level.in_(
                        [PermissionLevel.VIEW, PermissionLevel.DOWNLOAD]
                    ),
                    *_active_permission_conditions(),
                )
                .first()
                is not None
            )
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Document preview authorization lookup failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Document request failed",
        )

    if document is None or not has_view_access:
        _commit_access_audit(
            db,
            AuditEvent(
                actor_id=current_user.id,
                actor_email=current_user.email,
                action=AuditAction.ACCESS_DENIED,
                resource_id=document_id[:255],
                outcome=AuditOutcome.DENIED,
                reason="Document not found or view permission not granted",
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    storage_path = _resolve_document_storage_path(document.storage_path)
    if storage_path is None:
        _commit_access_audit(
            db,
            AuditEvent(
                actor_id=current_user.id,
                actor_email=current_user.email,
                action=AuditAction.DOCUMENT_READ,
                resource_id=document.id,
                outcome=AuditOutcome.ERROR,
                reason="Stored document is unavailable",
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document file not found",
        )

    _verify_document_integrity(
        document,
        storage_path,
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
            context_metadata={"operation": "preview"},
        ),
    )
    return FileResponse(
        path=storage_path,
        media_type=document.content_type,
        filename=document.name,
        content_disposition_type="inline",
        headers={"X-Content-Type-Options": "nosniff"},
    )


@router.get(
    "/{document_id}/download",
    response_class=FileResponse,
    summary="Download an authorized document",
)
def download_document(
    document_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> FileResponse:
    """Download a document owned by the user or explicitly shared for download."""
    try:
        document = db.query(Document).filter(Document.id == document_id).first()
        if document is None:
            has_download_access = False
        elif document.owner_id == current_user.id:
            has_download_access = True
        else:
            has_download_access = (
                db.query(DocumentPermission)
                .filter(
                    DocumentPermission.document_id == document.id,
                    DocumentPermission.grantee_id == current_user.id,
                    DocumentPermission.permission_level == PermissionLevel.DOWNLOAD,
                    *_active_permission_conditions(),
                )
                .first()
                is not None
            )
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Document download authorization lookup failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Document request failed",
        )

    if document is None or not has_download_access:
        _commit_access_audit(
            db,
            AuditEvent(
                actor_id=current_user.id,
                actor_email=current_user.email,
                action=AuditAction.ACCESS_DENIED,
                resource_id=document_id[:255],
                outcome=AuditOutcome.DENIED,
                reason="Document not found or download permission not granted",
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    storage_path = _resolve_document_storage_path(document.storage_path)
    if storage_path is None:
        _commit_access_audit(
            db,
            AuditEvent(
                actor_id=current_user.id,
                actor_email=current_user.email,
                action=AuditAction.DOCUMENT_DOWNLOAD,
                resource_id=document.id,
                outcome=AuditOutcome.ERROR,
                reason="Stored document is unavailable",
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document file not found",
        )

    _verify_document_integrity(
        document,
        storage_path,
        current_user,
        db,
        AuditAction.DOCUMENT_DOWNLOAD,
    )
    _commit_access_audit(
        db,
        AuditEvent(
            actor_id=current_user.id,
            actor_email=current_user.email,
            action=AuditAction.DOCUMENT_DOWNLOAD,
            resource_id=document.id,
            outcome=AuditOutcome.SUCCESS,
        ),
    )
    return FileResponse(
        path=storage_path,
        media_type=document.content_type,
        filename=document.name,
    )


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
    "/shared-with-me",
    response_model=list[SharedDocumentResponse],
    summary="List documents shared with the current user",
)
def list_shared_documents(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[SharedDocumentResponse]:
    """List documents with active grants for the authenticated user."""
    try:
        rows = (
            db.query(
                Document,
                User.name,
                User.email,
                DocumentPermission.permission_level,
            )
            .join(DocumentPermission, DocumentPermission.document_id == Document.id)
            .outerjoin(User, User.id == Document.owner_id)
            .filter(
                DocumentPermission.grantee_id == current_user.id,
                *_active_permission_conditions(),
            )
            .order_by(Document.created_at.desc())
            .all()
        )
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Shared document listing failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Document request failed",
        )

    shared_documents: dict[str, SharedDocumentResponse] = {}
    for document, owner_name, owner_email, permission_level in rows:
        shared = shared_documents.get(document.id)
        if shared is None:
            shared_documents[document.id] = SharedDocumentResponse(
                id=document.id,
                filename=document.name,
                owner_id=document.owner_id,
                owner_name=owner_name,
                owner_email=owner_email,
                permissions=[SharePermission(permission_level.value)],
                file_size=document.file_size,
                content_type=document.content_type,
                created_at=document.created_at,
            )
        else:
            shared.permissions.append(SharePermission(permission_level.value))

    _commit_access_audit(
        db,
        AuditEvent(
            actor_id=current_user.id,
            actor_email=current_user.email,
            action=AuditAction.DOCUMENT_READ,
            outcome=AuditOutcome.SUCCESS,
            context_metadata={
                "operation": "list_shared",
                "document_count": len(shared_documents),
            },
        ),
    )
    return list(shared_documents.values())


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
        "The authenticated user becomes its owner. File access uses separate authorized endpoints."
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
    digest = hashlib.sha256()
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
                digest.update(chunk)

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
        sha256=digest.hexdigest(),
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
