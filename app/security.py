"""Cryptographic utilities for TrustVault.

Provides Argon2id password hashing and JWT token creation/validation.
No database access. No logging of secrets, hashes, or tokens.
"""

from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.config import settings

# Argon2id hasher — OWASP-recommended parameters
_ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)
_JWT_ALGORITHM = "HS256"


def hash_password(plaintext: str) -> str:
    """Hash a plaintext password with Argon2id.

    The returned string starts with '$argon2id$' and includes the salt,
    parameters, and hash. The plaintext is used transiently; never logged.
    """
    return _ph.hash(plaintext)


def verify_password(plaintext: str, hashed: str) -> bool:
    """Verify a plaintext password against an Argon2id hash.

    Returns True if the password matches, False on any mismatch or error.
    Never raises to the caller. Never logs either argument.
    """
    try:
        return _ph.verify(hashed, plaintext)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def create_access_token(subject: str, expires_delta: timedelta | None = None) -> str:
    """Create a signed JWT access token.

    Args:
        subject: The user UUID string. Never email, name, or role.
        expires_delta: Custom expiry offset. Defaults to settings.ACCESS_TOKEN_EXPIRE_MINUTES.

    The token payload contains only: sub (UUID), iat, exp.
    settings.SECRET_KEY is read from configuration and never logged.
    """
    now = datetime.now(timezone.utc)
    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": subject,
        "iat": now,
        "exp": now + expires_delta,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=_JWT_ALGORITHM)


def decode_access_token(token: str) -> str:
    """Decode and validate a JWT access token.

    Returns the subject (user UUID string) on success.
    Raises ValueError with a generic safe message on any failure:
      - Expired token
      - Invalid signature
      - Malformed token
      - Missing 'sub' claim

    The caller is responsible for verifying the user exists and is active.
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[_JWT_ALGORITHM],
        )
        subject: str | None = payload.get("sub")
        if not subject:
            raise ValueError("Invalid or expired token")
        return subject
    except jwt.ExpiredSignatureError:
        raise ValueError("Invalid or expired token")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid or expired token")
