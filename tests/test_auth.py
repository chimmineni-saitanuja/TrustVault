"""Authentication and authorization endpoint tests."""

import unittest
from datetime import timedelta
from unittest.mock import patch

from sqlalchemy.exc import SQLAlchemyError
from starlette.testclient import TestClient

from app.database import get_db
from app.main import app
from app.models import AuditAction, AuditEvent, AuditOutcome, User, UserRole
from app.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from tests.conftest import (
    TestingSessionLocal,
    make_user,
    setup_test_db,
    teardown_test_db,
    test_engine,
)


class TestAuthenticationAndAuthorization(unittest.TestCase):
    """Exercise auth endpoints against an isolated in-memory database."""

    @classmethod
    def setUpClass(cls):
        setup_test_db()

    @classmethod
    def tearDownClass(cls):
        teardown_test_db()

    def setUp(self):
        self.connection = test_engine.connect()
        self.transaction = self.connection.begin()
        self.session = TestingSessionLocal(bind=self.connection)

        def _override_get_db():
            yield self.session

        app.dependency_overrides[get_db] = _override_get_db
        self.client = TestClient(app)

    def tearDown(self):
        app.dependency_overrides.clear()
        self.session.close()
        if self.transaction.is_active:
            self.transaction.rollback()
        self.connection.close()

    def _authorization(self, user: User) -> dict[str, str]:
        token = create_access_token(user.id)
        return {"Authorization": f"Bearer {token}"}

    def test_registration_hashes_password_and_forces_viewer_role(self):
        response = self.client.post(
            "/auth/register",
            json={
                "name": "New User",
                "email": "new@example.com",
                "password": "password8",
                "role": "admin",
            },
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["role"], UserRole.VIEWER.value)
        self.assertNotIn("password_hash", response.json())
        user = self.session.query(User).filter_by(email="new@example.com").one()
        self.assertTrue(user.password_hash.startswith("$argon2id$"))
        self.assertTrue(verify_password("password8", user.password_hash))
        self.assertFalse(verify_password("incorrect", user.password_hash))
        event = self.session.query(AuditEvent).one()
        self.assertEqual(event.action, AuditAction.USER_REGISTER)
        self.assertEqual(event.outcome, AuditOutcome.SUCCESS)

    def test_registration_only_enforces_minimum_password_length(self):
        response = self.client.post(
            "/auth/register",
            json={
                "name": "New User",
                "email": "short@example.com",
                "password": "short",
            },
        )
        self.assertEqual(response.status_code, 422)

    def test_duplicate_registration_is_safe(self):
        make_user(self.session, email="duplicate@example.com")

        response = self.client.post(
            "/auth/register",
            json={
                "name": "Another User",
                "email": "duplicate@example.com",
                "password": "password8",
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "Email already registered")
        self.assertNotIn("IntegrityError", response.text)

    def test_registration_rolls_back_if_audit_persistence_fails(self):
        with (
            patch.object(self.session, "commit", side_effect=SQLAlchemyError("database failure")),
            patch.object(self.session, "rollback", wraps=self.session.rollback) as rollback,
        ):
            response = self.client.post(
                "/auth/register",
                json={
                    "name": "New User",
                    "email": "audit-failure@example.com",
                    "password": "password8",
                },
            )

        self.assertEqual(response.status_code, 500)
        rollback.assert_called_once()
        self.assertIsNone(
            self.session.query(User).filter_by(email="audit-failure@example.com").first()
        )
        self.assertEqual(self.session.query(AuditEvent).count(), 0)

    def test_login_returns_token_and_records_success_audit(self):
        user = make_user(self.session, email="login@example.com", password="password8")

        response = self.client.post(
            "/auth/login",
            json={"email": user.email, "password": "password8"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["token_type"], "bearer")
        self.assertEqual(decode_access_token(response.json()["access_token"]), user.id)
        event = self.session.query(AuditEvent).one()
        self.assertEqual(event.action, AuditAction.LOGIN_SUCCESS)
        self.assertEqual(event.outcome, AuditOutcome.SUCCESS)

    def test_unknown_and_incorrect_password_failures_are_generic_and_audited(self):
        user = make_user(self.session, email="known@example.com", password="password8")

        unknown = self.client.post(
            "/auth/login",
            json={"email": "unknown@example.com", "password": "password8"},
        )
        incorrect = self.client.post(
            "/auth/login",
            json={"email": user.email, "password": "wrongpass"},
        )

        self.assertEqual(unknown.status_code, 401)
        self.assertEqual(incorrect.status_code, 401)
        self.assertEqual(unknown.json()["detail"], incorrect.json()["detail"])
        events = self.session.query(AuditEvent).order_by(AuditEvent.actor_email).all()
        self.assertEqual(len(events), 2)
        self.assertTrue(all(event.action == AuditAction.LOGIN_FAILED for event in events))
        self.assertTrue(all(event.outcome == AuditOutcome.DENIED for event in events))

    def test_login_audit_failure_rolls_back_and_does_not_succeed(self):
        user = make_user(self.session, email="audit-login@example.com", password="password8")

        with (
            patch.object(self.session, "commit", side_effect=SQLAlchemyError("database failure")),
            patch.object(self.session, "rollback", wraps=self.session.rollback) as rollback,
        ):
            response = self.client.post(
                "/auth/login",
                json={"email": user.email, "password": "password8"},
            )

        self.assertEqual(response.status_code, 500)
        rollback.assert_called_once()
        self.assertEqual(self.session.query(AuditEvent).count(), 0)

    def test_inactive_users_cannot_login_or_use_existing_tokens(self):
        user = make_user(self.session, email="inactive@example.com", password="password8")
        user.is_active = False
        self.session.commit()

        login = self.client.post(
            "/auth/login",
            json={"email": user.email, "password": "password8"},
        )
        profile = self.client.get("/auth/me", headers=self._authorization(user))

        self.assertEqual(login.status_code, 401)
        self.assertEqual(login.json()["detail"], "Invalid credentials")
        self.assertEqual(profile.status_code, 401)
        event = self.session.query(AuditEvent).one()
        self.assertEqual(event.action, AuditAction.LOGIN_FAILED)

    def test_jwt_rejects_invalid_signature_and_expiration(self):
        valid_token = create_access_token("user-id")
        header, payload, signature = valid_token.split(".")
        invalid_signature = f"{header}.{payload}.{signature[:-1]}{'A' if signature[-1] != 'A' else 'B'}"
        expired_token = create_access_token(
            "user-id",
            expires_delta=timedelta(seconds=-1),
        )

        with self.assertRaises(ValueError):
            decode_access_token(invalid_signature)
        with self.assertRaises(ValueError):
            decode_access_token(expired_token)

    def test_profile_and_protected_routes_require_valid_tokens(self):
        self.assertEqual(self.client.get("/auth/me").status_code, 401)
        self.assertEqual(self.client.get("/users/").status_code, 401)
        invalid = self.client.get(
            "/auth/me",
            headers={"Authorization": "Bearer invalid-token"},
        )
        self.assertEqual(invalid.status_code, 401)

        user = make_user(self.session, email="profile@example.com")
        profile = self.client.get("/auth/me", headers=self._authorization(user))
        self.assertEqual(profile.status_code, 200)
        self.assertEqual(profile.json()["email"], user.email)
        self.assertNotIn("password_hash", profile.json())

    def test_only_admin_can_list_users(self):
        viewer = make_user(self.session, email="viewer@example.com")
        owner = make_user(
            self.session,
            email="owner@example.com",
            role=UserRole.OWNER,
        )
        admin = make_user(
            self.session,
            email="admin@example.com",
            role=UserRole.ADMIN,
        )

        self.assertEqual(
            self.client.get("/users/", headers=self._authorization(viewer)).status_code,
            403,
        )
        self.assertEqual(
            self.client.get("/users/", headers=self._authorization(owner)).status_code,
            403,
        )
        response = self.client.get("/users/", headers=self._authorization(admin))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()), 3)
        self.assertTrue(all("password_hash" not in user for user in response.json()))
