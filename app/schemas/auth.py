"""Pydantic request and response schemas for authentication.

Security invariants:
- UserRegisterRequest has NO role field: role is always hardcoded to viewer in the router.
- UserPublicResponse has NO password_hash field: hashes are never returned to clients.
- Password is validated for minimum length only; never stored or logged in plaintext.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, field_validator

from app.models import UserRole


class UserRegisterRequest(BaseModel):
    """Input schema for user registration.

    The absence of a role field is intentional and security-critical.
    Any client-supplied role value is ignored: the router always assigns viewer.
    Pydantic's extra='ignore' silently drops unknown fields including a role key.
    """

    model_config = ConfigDict(extra="ignore")

    name: str
    email: EmailStr
    password: str

    @field_validator("name")
    @classmethod
    def name_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Name must not be blank")
        if len(v) > 120:
            raise ValueError("Name must be 120 characters or fewer")
        return v

    @field_validator("password")
    @classmethod
    def password_min_length(cls, v: str) -> str:
        """Enforce minimum password length.

        Only the length is checked here. Plaintext is never logged.
        """
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class UserLoginRequest(BaseModel):
    """Input schema for user login."""

    model_config = ConfigDict(extra="ignore")

    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    """Response schema for a successful login."""

    access_token: str
    token_type: Literal["bearer"] = "bearer"


class UserPublicResponse(BaseModel):
    """Public user profile.

    password_hash is intentionally absent.
    """

    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime
