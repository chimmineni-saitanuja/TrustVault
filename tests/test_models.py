"""Tests for database models, audit preservation, and audit log immutability."""

import unittest
from datetime import datetime, timezone
import uuid

from app.models import (
    AuditEvent,
    AuditAction,
    AuditOutcome,
    Document,
    DocumentPermission,
    DocumentStatus,
    PermissionLevel,
    ReadOnlyAuditLogError,
    User,
    UserRole,
)
from tests.conftest import setup_test_db, teardown_test_db, test_engine, TestingSessionLocal


class TestDatabaseModelsAndAudit(unittest.TestCase):
    """Test suite verifying schema models and audit log security invariants."""

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

    def tearDown(self):
        self.session.close()
        if self.transaction.is_active:
            self.transaction.rollback()
        self.connection.close()

    def test_user_creation_and_defaults(self):
        """Verify user creation with UUID generation and role enum."""
        user = User(
            name="Alice Owner",
            email="alice@example.com",
            password_hash="argon2id$v=19$m=65536,t=3,p=4$fakehash",
            role=UserRole.OWNER,
        )
        self.session.add(user)
        self.session.commit()

        self.assertIsNotNone(user.id)
        self.assertTrue(user.is_active)
        self.assertEqual(user.role, UserRole.OWNER)
        self.assertIsNotNone(user.created_at)

    def test_document_and_permission_creation(self):
        """Verify document creation and explicit permission granting."""
        owner = User(
            name="Bob Owner",
            email="bob@example.com",
            password_hash="fakehash",
            role=UserRole.OWNER,
        )
        viewer = User(
            name="Charlie Viewer",
            email="charlie@example.com",
            password_hash="fakehash",
            role=UserRole.VIEWER,
        )
        self.session.add_all([owner, viewer])
        self.session.commit()

        doc = Document(
            owner_id=owner.id,
            name="Q3_Financials.pdf",
            category="Finance",
            storage_path="storage/documents/uuid-q3.pdf",
            file_size=1024 * 500,
            content_type="application/pdf",
            status=DocumentStatus.ACTIVE,
        )
        self.session.add(doc)
        self.session.commit()

        perm = DocumentPermission(
            document_id=doc.id,
            grantee_id=viewer.id,
            granted_by_id=owner.id,
            permission_level=PermissionLevel.READ,
        )
        self.session.add(perm)
        self.session.commit()

        self.assertFalse(perm.is_revoked)
        self.assertEqual(perm.permission_level, PermissionLevel.READ)

    def test_audit_event_records_denied_attempt_with_context(self):
        """Verify audit trail faithfully records denied attempts with reason and context."""
        event = AuditEvent(
            actor_id=None,  # e.g., unauthenticated or anonymous attacker
            actor_email="attacker@external.com",
            action=AuditAction.ACCESS_DENIED,
            resource_id="doc-uuid-12345",
            outcome=AuditOutcome.DENIED,
            reason="Insufficient permissions: user does not hold READ access",
            ip_address="198.51.100.42",
            user_agent="curl/7.68.0",
            context_metadata={"attempted_action": "download", "header_auth_present": True},
        )
        self.session.add(event)
        self.session.commit()

        retrieved = self.session.query(AuditEvent).filter_by(id=event.id).first()
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.outcome, AuditOutcome.DENIED)
        self.assertEqual(retrieved.reason, "Insufficient permissions: user does not hold READ access")
        self.assertEqual(retrieved.context_metadata["attempted_action"], "download")
        self.assertEqual(retrieved.ip_address, "198.51.100.42")

    def test_audit_event_immutability_prevent_update(self):
        """Verify ordinary application code cannot modify an existing audit log entry."""
        event = AuditEvent(
            action=AuditAction.DOCUMENT_READ,
            resource_id="doc-uuid-9999",
            outcome=AuditOutcome.SUCCESS,
        )
        self.session.add(event)
        self.session.commit()

        # Attempt to modify audit record
        event.outcome = AuditOutcome.DENIED
        with self.assertRaises(ReadOnlyAuditLogError):
            self.session.commit()

    def test_audit_event_immutability_prevent_delete(self):
        """Verify ordinary application code cannot delete an existing audit log entry."""
        event = AuditEvent(
            action=AuditAction.DOCUMENT_DELETE,
            resource_id="doc-uuid-8888",
            outcome=AuditOutcome.SUCCESS,
        )
        self.session.add(event)
        self.session.commit()

        # Attempt to delete audit record
        self.session.delete(event)
        with self.assertRaises(ReadOnlyAuditLogError):
            self.session.commit()
