"""Authentication endpoints: registration, login, and profile.

Transaction policy (strict atomic rollback):
- POST /auth/register:  User row + AuditEvent committed atomically.
  IntegrityError (duplicate-email race) → explicit rollback → HTTP 400.
  Any other exception → explicit rollback → HTTP 500.
- POST /auth/login (all paths): AuditEvent committed before HTTP response is sent.
  If the audit commit fails → explicit rollback → HTTP 500 (not 401/200).

Security invariants:
- Passwords and hashes are never logged or returned.
- Tokens are never logged.
- Public registration always assigns the viewer role regardless of request body.
- Login failure messages are identical for "no account" and "wrong password" (no enumeration).
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user
from app.models import AuditAction, AuditEvent, AuditOutcome, User, UserRole
from app.schemas.auth import TokenResponse, UserLoginRequest, UserPublicResponse, UserRegisterRequest
from app.security import create_access_token, hash_password, verify_password

logger = logging.getLogger("trustvault.auth")

router = APIRouter()

# Generic failure message — shared across paths to prevent account enumeration.
_INVALID_CREDENTIALS = "Invalid credentials"


def _get_client_ip(request: Request) -> str | None:
    """Extract client IP address from request, respecting common proxy headers."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else None


def _get_user_agent(request: Request) -> str | None:
    """Extract User-Agent from request headers, truncated to 500 chars."""
    ua = request.headers.get("User-Agent", "")
    return ua[:500] if ua else None


def _commit_audit(db: Session, audit: AuditEvent, failure_message: str) -> None:
    """Persist an audit event before returning an authentication result."""
    try:
        db.add(audit)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        logger.error("%s", failure_message)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication failed due to an internal error",
        )


@router.post(
    "/register",
    response_model=UserPublicResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
    description=(
        "Creates a new user with the **viewer** role. "
        "Any client-supplied role field is silently ignored. "
        "Returns the public user profile without the password hash."
    ),
)
def register(
    request_body: UserRegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> UserPublicResponse:
    """Register a new user.

    Transaction: User row and USER_REGISTER audit event are committed atomically.
    A duplicate-email IntegrityError (race condition) maps to HTTP 400 after rollback.
    All other exceptions roll back and return HTTP 500.
    """
    try:
        existing = db.query(User).filter(User.email == request_body.email).first()
    except SQLAlchemyError:
        db.rollback()
        logger.error("Registration lookup failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed due to an internal error",
        )

    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    password_hash = hash_password(request_body.password)
    # password_hash is a local variable; request_body.password is not logged.

    new_user = User(
        name=request_body.name,
        email=request_body.email,
        password_hash=password_hash,
        role=UserRole.VIEWER,  # Always viewer — never taken from request body.
        is_active=True,
    )

    audit = AuditEvent(
        actor_email=request_body.email,
        action=AuditAction.USER_REGISTER,
        outcome=AuditOutcome.SUCCESS,
        ip_address=_get_client_ip(request),
        user_agent=_get_user_agent(request),
        context_metadata={"name": request_body.name},
    )

    try:
        db.add(new_user)
        db.add(audit)
        db.commit()  # Atomically commits both rows.
    except IntegrityError:
        # Race condition: duplicate email committed between the check above and commit.
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )
    except SQLAlchemyError:
        db.rollback()
        logger.error("Registration persistence failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed due to an internal error",
        )

    return UserPublicResponse.model_validate(new_user)


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate and receive a JWT access token",
    description=(
        "Returns a signed JWT on success. "
        "Failed attempts return HTTP 401 only after the required audit event is committed. "
        "Login failure messages are generic to prevent account enumeration."
    ),
)
def login(
    request_body: UserLoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Authenticate a user and issue a JWT.

    Transaction policy (strict):
    - Every code path writes an AuditEvent and commits it before returning the HTTP response.
    - If the audit commit fails, db.rollback() is called and HTTP 500 is returned.
    - HTTP 401 is only returned after the corresponding AuditEvent(DENIED) is durably committed.
    """
    ip = _get_client_ip(request)
    ua = _get_user_agent(request)

    try:
        user = db.query(User).filter(User.email == request_body.email).first()
    except SQLAlchemyError:
        db.rollback()
        logger.error("Login user lookup failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed due to an internal error",
        )

    # Path 1: no account with supplied email.
    if user is None:
        audit = AuditEvent(
            actor_id=None,
            actor_email=request_body.email,
            action=AuditAction.LOGIN_FAILED,
            outcome=AuditOutcome.DENIED,
            reason="Invalid credentials",
            ip_address=ip,
            user_agent=ua,
        )
        _commit_audit(db, audit, "Failed-login audit persistence failed")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_INVALID_CREDENTIALS,
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Path 2: account found but password does not match.
    if not verify_password(request_body.password, user.password_hash):
        # Passwords and hashes are not passed to the logger.
        audit = AuditEvent(
            actor_id=user.id,
            actor_email=user.email,
            action=AuditAction.LOGIN_FAILED,
            outcome=AuditOutcome.DENIED,
            reason="Bad password",
            ip_address=ip,
            user_agent=ua,
        )
        _commit_audit(db, audit, "Failed-login audit persistence failed")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_INVALID_CREDENTIALS,  # Same as Path 1 — no enumeration.
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Path 3: correct password but account is inactive.
    if not user.is_active:
        audit = AuditEvent(
            actor_id=user.id,
            actor_email=user.email,
            action=AuditAction.LOGIN_FAILED,
            outcome=AuditOutcome.DENIED,
            reason="Invalid credentials",
            ip_address=ip,
            user_agent=ua,
        )
        _commit_audit(db, audit, "Failed-login audit persistence failed")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_INVALID_CREDENTIALS,
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Path 4: success.
    token = create_access_token(subject=user.id)
    # Token value is not logged.

    audit = AuditEvent(
        actor_id=user.id,
        actor_email=user.email,
        action=AuditAction.LOGIN_SUCCESS,
        outcome=AuditOutcome.SUCCESS,
        ip_address=ip,
        user_agent=ua,
    )
    _commit_audit(db, audit, "Login-success audit persistence failed")

    return TokenResponse(access_token=token)


@router.get(
    "/me",
    response_model=UserPublicResponse,
    summary="Return the authenticated user's own profile",
    description=(
        "Returns the profile of the currently authenticated user. "
        "**No audit event is generated** for this endpoint — reading your own profile "
        "is not considered a security-relevant event in this system."
    ),
)
def me(current_user: User = Depends(get_current_user)) -> UserPublicResponse:
    """Return the authenticated user's profile.

    Deliberate design decision: no audit event is written here.
    Only operations that modify state or access other users' resources are audited.
    """
    return UserPublicResponse.model_validate(current_user)
