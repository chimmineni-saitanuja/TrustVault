"""Interactively create the first administrator account."""

from getpass import getpass
import logging
import sys

from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.database import SessionLocal, engine
from app.models import AuditAction, AuditEvent, AuditOutcome, User, UserRole
from app.security import hash_password

logger = logging.getLogger("trustvault.bootstrap")
_BOOTSTRAP_LOCK_ID = 684322190471


def main() -> None:
    if not sys.stdin.isatty():
        raise SystemExit("Run this command in an interactive terminal.")

    name = input("Administrator name: ").strip()
    email = input("Administrator email: ").strip().lower()
    password = getpass("Administrator password (minimum 12 characters): ")
    confirmation = getpass("Confirm password: ")
    if not name or len(name) > 120:
        raise SystemExit("Name must contain 1 to 120 characters.")
    from app.schemas.auth import UserRegisterRequest

    try:
        email = str(
            UserRegisterRequest(name=name, email=email, password=password).email
        ).lower()
    except ValidationError as exc:
        raise SystemExit("Enter a valid name, email address, and password.") from exc
    if len(password) < 12:
        raise SystemExit("Administrator password must be at least 12 characters.")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")

    session = SessionLocal()
    try:
        if engine.dialect.name == "postgresql":
            session.execute(
                text("SELECT pg_advisory_xact_lock(:lock_id)"),
                {"lock_id": _BOOTSTRAP_LOCK_ID},
            )
        elif engine.dialect.name == "sqlite":
            session.execute(text("BEGIN IMMEDIATE"))
        if session.query(User).filter(User.role == UserRole.ADMIN).first() is not None:
            raise SystemExit("An administrator already exists; bootstrap is one-time only.")
        if session.query(User).filter(User.email == email).first() is not None:
            raise SystemExit("That email address is already registered.")

        admin = User(
            name=name,
            email=email,
            password_hash=hash_password(password),
            role=UserRole.ADMIN,
            is_active=True,
        )
        session.add(admin)
        session.flush()
        session.add(
            AuditEvent(
                actor_id=admin.id,
                actor_email=admin.email,
                action=AuditAction.ADMIN_BOOTSTRAP,
                outcome=AuditOutcome.SUCCESS,
            )
        )
        session.commit()
        print(f"Administrator account created for {email}.")
    except SystemExit:
        session.rollback()
        raise
    except SQLAlchemyError:
        session.rollback()
        logger.exception("Administrator bootstrap failed")
        raise SystemExit("Administrator bootstrap failed; review server logs.")
    finally:
        session.close()


if __name__ == "__main__":
    main()
