"""FastAPI dependency functions for authentication and role enforcement.

All error messages are generic to avoid leaking internal state.
No passwords, tokens, or secret keys are logged.
"""

from collections.abc import Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, UserRole
from app.security import decode_access_token

_bearer = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    """Validate a Bearer token and return the corresponding active User.

    Raises HTTP 401 for:
    - Missing or non-Bearer Authorization header.
    - Token that fails signature, expiry, or subject validation.
    - Subject UUID that does not match any user in the database.
    - User whose is_active flag is False.

    The same generic message is used for token-decode and not-found failures
    to prevent enumeration of valid user UUIDs via the token subject.
    """
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        user_id = decode_access_token(credentials.credentials)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.get(User, user_id)
    if user is None:
        # Same message as token decode failure — prevents UUID enumeration.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_role(*roles: UserRole) -> Callable:
    """Return a FastAPI dependency that enforces one of the specified roles.

    Calls get_current_user first, so all 401 rules apply before the 403 check.
    Returns HTTP 403 if the user's role is not in the allowed set.
    The error message does not reveal which roles are permitted.
    """
    def _dependency(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return current_user

    return _dependency
