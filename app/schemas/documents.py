"""Public document metadata schemas."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models import DocumentStatus


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
