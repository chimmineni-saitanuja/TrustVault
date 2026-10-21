"""Authenticated document upload endpoint."""

import codecs
import logging
from pathlib import Path
import uuid

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.dependencies import get_current_user
from app.models import AuditAction, AuditEvent, AuditOutcome, Document, User
from app.schemas.documents import DocumentUploadResponse

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
