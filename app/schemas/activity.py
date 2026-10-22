"""Safe public schema for authenticated activity history."""

from datetime import datetime

from pydantic import BaseModel

from app.models import AuditOutcome


class ActivityEventResponse(BaseModel):
    """An activity entry with only details safe for its authenticated actor."""

    id: str
    action: str
    outcome: AuditOutcome
    created_at: datetime
    document_id: str | None
    document_name: str | None
    related_user_name: str | None
    related_user_email: str | None
