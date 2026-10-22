"""Tests for authenticated activity history and safe detail filtering."""

import unittest
from datetime import datetime, timedelta, timezone

from starlette.testclient import TestClient

from app.database import get_db
from app.main import app
from app.models import (
    AuditAction,
    AuditEvent,
    AuditOutcome,
    Document,
    DocumentPermission,
    PermissionLevel,
)
from app.security import create_access_token
from tests.conftest import (
    TestingSessionLocal,
    make_user,
    setup_test_db,
    teardown_test_db,
    test_engine,
)


class TestActivityLog(unittest.TestCase):
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

    def _authorization(self, user) -> dict[str, str]:
        return {"Authorization": "Bearer " + create_access_token(user.id)}

    def _make_document(self, owner, name: str) -> Document:
        document = Document(
            owner_id=owner.id,
            name=name,
            storage_path=f"private-{name}.pdf",
            file_size=12,
            content_type="application/pdf",
        )
        self.session.add(document)
        self.session.commit()
        return document

    def test_activity_requires_authentication(self):
        response = self.client.get("/activity/")

        self.assertEqual(response.status_code, 401)

    def test_activity_is_actor_scoped_and_returns_only_safe_authorized_details(self):
        actor = make_user(self.session, name="Owner One", email="activity-owner@example.com")
        recipient = make_user(
            self.session,
            name="Recipient Two",
            email="activity-recipient@example.com",
        )
        other_user = make_user(self.session, name="Other User", email="activity-other@example.com")
        owned_document = self._make_document(actor, "owned-report")
        other_document = self._make_document(other_user, "other-private-report")
        self.session.add_all(
            [
                AuditEvent(
                    actor_id=actor.id,
                    actor_email=actor.email,
                    action=AuditAction.PERMISSION_GRANT,
                    resource_id=owned_document.id,
                    outcome=AuditOutcome.SUCCESS,
                    ip_address="private-ip-marker",
                    user_agent="private-agent-marker",
                    reason="private-reason-marker",
                    context_metadata={
                        "grantee_id": recipient.id,
                        "password": "private-password-marker",
                        "storage_path": "private/storage-marker",
                    },
                ),
                AuditEvent(
                    actor_id=actor.id,
                    actor_email=actor.email,
                    action=AuditAction.ACCESS_DENIED,
                    resource_id=other_document.id,
                    outcome=AuditOutcome.DENIED,
                    context_metadata={"attempted_action": "preview"},
                ),
                AuditEvent(
                    actor_id=other_user.id,
                    actor_email=other_user.email,
                    action=AuditAction.DOCUMENT_UPLOAD,
                    resource_id=other_document.id,
                    outcome=AuditOutcome.SUCCESS,
                ),
            ]
        )
        self.session.commit()

        response = self.client.get(
            "/activity/",
            headers=self._authorization(actor),
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(len(payload), 2)
        share_event = next(event for event in payload if event["action"] == "permission.grant")
        denied_event = next(event for event in payload if event["outcome"] == "denied")
        self.assertEqual(share_event["document_id"], owned_document.id)
        self.assertEqual(share_event["document_name"], owned_document.name)
        self.assertEqual(share_event["related_user_name"], recipient.name)
        self.assertEqual(share_event["related_user_email"], recipient.email)
        self.assertIsNone(denied_event["document_id"])
        self.assertIsNone(denied_event["document_name"])
        self.assertNotIn(other_document.name, response.text)
        self.assertNotIn("private-ip-marker", response.text)
        self.assertNotIn("private-agent-marker", response.text)
        self.assertNotIn("private-reason-marker", response.text)
        self.assertNotIn("private-password-marker", response.text)
        self.assertNotIn("private/storage-marker", response.text)
        self.assertNotIn(other_user.email, response.text)

    def test_expired_share_does_not_reveal_document_in_activity(self):
        owner = make_user(self.session, email="activity-expiry-owner@example.com")
        recipient = make_user(self.session, email="activity-expiry-recipient@example.com")
        document = self._make_document(owner, "expired-share-document")
        self.session.add_all(
            [
                DocumentPermission(
                    document_id=document.id,
                    grantee_id=recipient.id,
                    granted_by_id=owner.id,
                    permission_level=PermissionLevel.VIEW,
                    is_revoked=False,
                    expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
                ),
                AuditEvent(
                    actor_id=recipient.id,
                    actor_email=recipient.email,
                    action=AuditAction.DOCUMENT_READ,
                    resource_id=document.id,
                    outcome=AuditOutcome.SUCCESS,
                ),
            ]
        )
        self.session.commit()

        response = self.client.get(
            "/activity/",
            headers=self._authorization(recipient),
        )

        self.assertEqual(response.status_code, 200)
        event = response.json()[0]
        self.assertIsNone(event["document_id"])
        self.assertIsNone(event["document_name"])
        self.assertNotIn(document.name, response.text)
