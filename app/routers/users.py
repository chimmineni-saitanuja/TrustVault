"""Admin-only user management endpoints.

Demonstrates server-side role enforcement: authorization is checked on the
backend, not by hiding frontend buttons. Direct API requests from users with
incorrect roles are rejected at the dependency layer before any data is queried.
"""

import logging
from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_role
from app.models import User, UserRole
from app.schemas.auth import UserPublicResponse

logger = logging.getLogger("trustvault.users")

router = APIRouter()


@router.get(
    "/",
    response_model=List[UserPublicResponse],
    summary="List all users (admin only)",
    description=(
        "Returns all registered user accounts. **Requires admin role.** "
        "Unauthenticated requests receive HTTP 401. "
        "Non-admin authenticated requests receive HTTP 403. "
        "password_hash is never included in the response."
    ),
)
def list_users(
    _current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> List[UserPublicResponse]:
    """Return all users. Accessible only to admins.

    password_hash is excluded by UserPublicResponse schema.
    """
    users = db.query(User).order_by(User.created_at).all()
    return [UserPublicResponse.model_validate(u) for u in users]
