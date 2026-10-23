"""Tests for administrator access and document review workflow."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from starlette.testclient import TestClient

from app.config import settings
from app.database import get_db
from app.main import app
from app.models import (
    AuditAction,
    AuditEvent,
    Document,
    DocumentPermission,
    DocumentReviewStatus,
    DocumentStatus,
    PermissionLevel,
    User,
    UserRole,
)
from app.security import create_access_token
from tests.conftest import (
    TestingSessionLocal,
    make_user,
    setup_test_db,
    teardown_test_db,
    test_engine,
)


class TestAdminReview(unittest.TestCase):
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
        self.storage = tempfile.TemporaryDirectory()
        self.storage_setting = patch.object(settings, "STORAGE_DIR", self.storage.name)
        self.storage_setting.start()

        def _override_get_db():
            yield self.session

        app.dependency_overrides[get_db] = _override_get_db
        self.client = TestClient(app)

    def tearDown(self):
        self.storage_setting.stop()
        app.dependency_overrides.clear()
        self.session.close()
        if self.transaction.is_active:
            self.transaction.rollback()
        self.connection.close()
        self.storage.cleanup()

    def _authorization(self, user: User) -> dict[str, str]:
        return {"Authorization": f"Bearer {create_access_token(user.id)}"}

    def _make_document(
        self,
        owner: User,
        name: str,
        review_status: DocumentReviewStatus = DocumentReviewStatus.PENDING,
    ) -> Document:
        document = Document(
            owner_id=owner.id,
            name=name,
            storage_path=f"{name}.txt",
            file_size=16,
            content_type="text/plain",
            review_status=review_status,
            status=DocumentStatus.ACTIVE,
        )
        self.session.add(document)
        self.session.commit()
        return document

    def test_non_admin_cannot_read_dashboard_or_review_documents(self):
        owner = make_user(self.session, email="admin-denied-owner@example.com")
        document = self._make_document(owner, "awaiting-review")
        headers = self._authorization(owner)

        dashboard = self.client.get("/admin/dashboard", headers=headers)
        approve = self.client.post(
            f"/admin/documents/{document.id}/approve",
            headers=headers,
        )
        reject = self.client.post(
            f"/admin/documents/{document.id}/reject",
            headers=headers,
            json={"reason": "not for viewer"},
        )

        self.assertEqual(dashboard.status_code, 403)
        self.assertEqual(approve.status_code, 403)
        self.assertEqual(reject.status_code, 403)
        self.assertEqual(document.review_status, DocumentReviewStatus.PENDING)

    def test_public_registration_cannot_create_an_admin(self):
        response = self.client.post(
            "/auth/register",
            json={
                "name": "Public Admin Attempt",
                "email": "public-admin-attempt@example.com",
                "password": "safe-password",
                "role": "admin",
            },
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["role"], UserRole.VIEWER.value)

    def test_admin_dashboard_returns_users_safe_activity_and_pending_documents(self):
        admin = make_user(
            self.session,
            email="dashboard-admin@example.com",
            role=UserRole.ADMIN,
        )
        owner = make_user(self.session, email="dashboard-owner@example.com")
        document = self._make_document(owner, "dashboard-pending")
        self.session.add(
            AuditEvent(
                actor_id=owner.id,
                actor_email=owner.email,
                action=AuditAction.DOCUMENT_UPLOAD,
                resource_id=document.id,
                outcome="success",
                context_metadata={"storage_path": "private-marker"},
                ip_address="private-ip-marker",
            )
        )
        self.session.commit()

        response = self.client.get(
            "/admin/dashboard",
            headers=self._authorization(admin),
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(len(payload["users"]), 2)
        self.assertEqual(len(payload["pending_documents"]), 1)
        self.assertEqual(payload["pending_documents"][0]["id"], document.id)
        self.assertEqual(payload["activity"][0]["document_name"], document.name)
        self.assertNotIn("password_hash", response.text)
        self.assertNotIn("storage_path", response.text)
        self.assertNotIn("private-marker", response.text)
        self.assertNotIn("private-ip-marker", response.text)

    def test_admin_can_approve_pending_document_and_access_is_enabled(self):
        admin = make_user(self.session, email="approve-admin@example.com", role=UserRole.ADMIN)
        owner = make_user(self.session, email="approve-owner@example.com")
        recipient = make_user(self.session, email="approve-recipient@example.com")
        document = self._make_document(owner, "approve-me")
        content = b"reviewed owner document"
        (Path(self.storage.name) / document.storage_path).write_bytes(content)

        response = self.client.post(
            f"/admin/documents/{document.id}/approve",
            headers=self._authorization(admin),
        )
        owner_download = self.client.get(
            f"/documents/{document.id}/download",
            headers=self._authorization(owner),
        )
        share = self.client.post(
            f"/documents/{document.id}/shares",
            headers=self._authorization(owner),
            json={"user_id": recipient.id, "permission": "download"},
        )
        recipient_download = self.client.get(
            f"/documents/{document.id}/download",
            headers=self._authorization(recipient),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["review_status"], "approved")
        self.assertEqual(owner_download.status_code, 200)
        self.assertEqual(owner_download.content, content)
        self.assertEqual(share.status_code, 201)
        self.assertEqual(recipient_download.status_code, 200)
        self.assertEqual(recipient_download.content, content)
        event = (
            self.session.query(AuditEvent)
            .filter_by(action=AuditAction.DOCUMENT_APPROVE)
            .one()
        )
        self.assertEqual(event.actor_id, admin.id)

    def test_rejection_requires_reason_and_blocks_file_and_sharing_access(self):
        admin = make_user(self.session, email="reject-admin@example.com", role=UserRole.ADMIN)
        owner = make_user(self.session, email="reject-owner@example.com")
        recipient = make_user(self.session, email="reject-recipient@example.com")
        document = self._make_document(owner, "reject-me")
        content = b"not approved"
        (Path(self.storage.name) / document.storage_path).write_bytes(content)
        headers = self._authorization(admin)

        missing_reason = self.client.post(
            f"/admin/documents/{document.id}/reject",
            headers=headers,
            json={"reason": "   "},
        )
        rejected = self.client.post(
            f"/admin/documents/{document.id}/reject",
            headers=headers,
            json={"reason": "Please remove sensitive content."},
        )
        owner_listing = self.client.get(
            "/documents/",
            headers=self._authorization(owner),
        )
        owner_detail = self.client.get(
            f"/documents/{document.id}",
            headers=self._authorization(owner),
        )
        preview = self.client.get(
            f"/documents/{document.id}/preview",
            headers=self._authorization(owner),
        )
        download = self.client.get(
            f"/documents/{document.id}/download",
            headers=self._authorization(owner),
        )
        share = self.client.post(
            f"/documents/{document.id}/shares",
            headers=self._authorization(owner),
            json={"user_id": recipient.id, "permission": "view"},
        )

        self.assertEqual(missing_reason.status_code, 422)
        self.assertEqual(rejected.status_code, 200)
        self.assertEqual(rejected.json()["review_status"], "rejected")
        self.assertEqual(
            rejected.json()["rejection_reason"],
            "Please remove sensitive content.",
        )
        self.assertEqual(
            owner_listing.json()[0]["rejection_reason"],
            "Please remove sensitive content.",
        )
        self.assertEqual(owner_detail.status_code, 404)
        self.assertEqual(preview.status_code, 404)
        self.assertEqual(download.status_code, 404)
        self.assertEqual(share.status_code, 409)
        event = (
            self.session.query(AuditEvent)
            .filter_by(action=AuditAction.DOCUMENT_REJECT)
            .one()
        )
        self.assertEqual(event.actor_id, admin.id)

    def test_only_admin_can_preview_a_pending_document_for_review(self):
        admin = make_user(self.session, email="review-preview-admin@example.com", role=UserRole.ADMIN)
        owner = make_user(self.session, email="review-preview-owner@example.com")
        document = self._make_document(owner, "review-preview")
        content = b"private pending content"
        (Path(self.storage.name) / document.storage_path).write_bytes(content)

        owner_preview = self.client.get(
            f"/admin/documents/{document.id}/preview",
            headers=self._authorization(owner),
        )
        admin_preview = self.client.get(
            f"/admin/documents/{document.id}/preview",
            headers=self._authorization(admin),
        )

        self.assertEqual(owner_preview.status_code, 403)
        self.assertEqual(admin_preview.status_code, 200)
        self.assertEqual(admin_preview.content, content)

    def test_pending_documents_are_hidden_from_shared_access_until_approved(self):
        owner = make_user(self.session, email="pending-share-owner@example.com")
        recipient = make_user(self.session, email="pending-share-recipient@example.com")
        document = self._make_document(owner, "pending-shared")
        content = b"awaiting admin review"
        (Path(self.storage.name) / document.storage_path).write_bytes(content)
        self.session.add(
            DocumentPermission(
                document_id=document.id,
                grantee_id=recipient.id,
                granted_by_id=owner.id,
                permission_level=PermissionLevel.DOWNLOAD,
                is_revoked=False,
            )
        )
        self.session.commit()

        shared = self.client.get(
            "/documents/shared-with-me",
            headers=self._authorization(recipient),
        )
        preview = self.client.get(
            f"/documents/{document.id}/preview",
            headers=self._authorization(recipient),
        )
        download = self.client.get(
            f"/documents/{document.id}/download",
            headers=self._authorization(recipient),
        )

        self.assertEqual(shared.status_code, 200)
        self.assertEqual(shared.json(), [])
        self.assertEqual(preview.status_code, 404)
        self.assertEqual(download.status_code, 404)

    def test_admin_dashboard_counts_all_document_review_states(self):
        admin = make_user(self.session, email="counts-admin@example.com", role=UserRole.ADMIN)
        owner = make_user(self.session, email="counts-owner@example.com")
        self._make_document(owner, "counts-pending", DocumentReviewStatus.PENDING)
        self._make_document(owner, "counts-approved", DocumentReviewStatus.APPROVED)
        self._make_document(owner, "counts-rejected", DocumentReviewStatus.REJECTED)

        response = self.client.get("/admin/dashboard", headers=self._authorization(admin))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["total_users"], 2)
        self.assertEqual(payload["total_documents"], 3)
        self.assertEqual(payload["pending_reviews"], 1)
        self.assertEqual(payload["approved_documents"], 1)
        self.assertEqual(payload["rejected_documents"], 1)

    def test_admin_document_search_and_preview_are_protected(self):
        admin = make_user(self.session, email="search-admin@example.com", role=UserRole.ADMIN)
        owner = make_user(self.session, email="search-owner@example.com")
        other_owner = make_user(self.session, email="search-other@example.com")
        doc = self._make_document(owner, "searchable-report")
        self._make_document(other_owner, "unrelated-file", DocumentReviewStatus.APPROVED)
        (Path(self.storage.name) / doc.storage_path).write_bytes(b"pending admin preview")

        search = self.client.get(
            "/admin/documents",
            params={"owner_id": owner.id, "filename": "report", "review_status": "pending"},
            headers=self._authorization(admin),
        )
        owner_search = self.client.get("/admin/documents", headers=self._authorization(owner))
        admin_preview = self.client.get(
            f"/admin/documents/{doc.id}/preview",
            headers=self._authorization(admin),
        )
        non_admin_preview = self.client.get(
            f"/admin/documents/{doc.id}/preview",
            headers=self._authorization(owner),
        )

        self.assertEqual(search.status_code, 200)
        self.assertEqual([row["id"] for row in search.json()], [doc.id])
        self.assertEqual(owner_search.status_code, 403)
        self.assertEqual(admin_preview.content, b"pending admin preview")
        self.assertEqual(non_admin_preview.status_code, 403)

    def test_user_management_audits_and_protects_last_active_admin(self):
        admin = make_user(self.session, email="users-admin@example.com", role=UserRole.ADMIN)
        target = make_user(self.session, email="users-target@example.com")
        headers = self._authorization(admin)

        deactivate = self.client.post(f"/admin/users/{target.id}/deactivate", headers=headers)
        inactive_token_response = self.client.get(
            "/auth/me",
            headers=self._authorization(target),
        )
        reactivate = self.client.post(f"/admin/users/{target.id}/reactivate", headers=headers)
        last_admin = self.client.post(f"/admin/users/{admin.id}/deactivate", headers=headers)

        self.assertEqual(deactivate.status_code, 200)
        self.assertFalse(deactivate.json()["is_active"])
        self.assertEqual(inactive_token_response.status_code, 401)
        self.assertEqual(reactivate.status_code, 200)
        self.assertTrue(reactivate.json()["is_active"])
        self.assertEqual(last_admin.status_code, 409)
        self.assertTrue(admin.is_active)
        actions = {
            event.action
            for event in self.session.query(AuditEvent)
            .filter(AuditEvent.resource_id == target.id)
            .all()
        }
        self.assertIn(AuditAction.USER_DEACTIVATE.value, actions)
        self.assertIn(AuditAction.USER_REACTIVATE.value, actions)

    def test_admin_permission_revocation_blocks_shared_read_and_download(self):
        admin = make_user(self.session, email="grant-admin@example.com", role=UserRole.ADMIN)
        owner = make_user(self.session, email="grant-owner@example.com")
        grantee = make_user(self.session, email="grant-recipient@example.com")
        document = self._make_document(owner, "grant-approved", DocumentReviewStatus.APPROVED)
        content = b"permission protected"
        (Path(self.storage.name) / document.storage_path).write_bytes(content)
        permission = DocumentPermission(
            document_id=document.id,
            grantee_id=grantee.id,
            granted_by_id=owner.id,
            permission_level=PermissionLevel.DOWNLOAD,
            is_revoked=False,
        )
        self.session.add(permission)
        self.session.commit()

        listing = self.client.get("/admin/permissions", headers=self._authorization(admin))
        revoke = self.client.delete(
            f"/admin/permissions/{permission.id}",
            headers=self._authorization(admin),
        )
        shared = self.client.get("/documents/shared-with-me", headers=self._authorization(grantee))
        preview = self.client.get(
            f"/documents/{document.id}/preview",
            headers=self._authorization(grantee),
        )
        download = self.client.get(
            f"/documents/{document.id}/download",
            headers=self._authorization(grantee),
        )

        self.assertEqual(listing.status_code, 200)
        self.assertEqual(listing.json()[0]["grantee_email"], grantee.email)
        self.assertEqual(revoke.status_code, 204)
        self.assertEqual(shared.json(), [])
        self.assertEqual(preview.status_code, 404)
        self.assertEqual(download.status_code, 404)
        revoke_event = (
            self.session.query(AuditEvent)
            .filter_by(action=AuditAction.PERMISSION_REVOKE.value, actor_id=admin.id)
            .one()
        )
        self.assertEqual(revoke_event.resource_id, document.id)

    def test_audit_filters_and_report_are_admin_only_and_safe(self):
        admin = make_user(self.session, email="audit-admin@example.com", role=UserRole.ADMIN)
        owner = make_user(self.session, email="audit-owner@example.com")
        document = self._make_document(owner, "=2+2", DocumentReviewStatus.APPROVED)
        self.session.add(
            AuditEvent(
                actor_id=owner.id,
                actor_email=owner.email,
                action=AuditAction.DOCUMENT_UPLOAD,
                resource_id=document.id,
                outcome="success",
                context_metadata={"secret_marker": "must-not-be-returned"},
                ip_address="private-address-marker",
            )
        )
        self.session.commit()

        filtered = self.client.get(
            "/admin/audit",
            params={"actor": "audit-owner", "action": AuditAction.DOCUMENT_UPLOAD.value, "outcome": "success"},
            headers=self._authorization(admin),
        )
        report = self.client.get(
            "/admin/reports/export",
            params={"actor": "audit-owner", "action": AuditAction.DOCUMENT_UPLOAD.value},
            headers=self._authorization(admin),
        )
        denied = self.client.get("/admin/audit", headers=self._authorization(owner))

        self.assertEqual(filtered.status_code, 200)
        self.assertEqual(len(filtered.json()), 1)
        self.assertNotIn("secret_marker", filtered.text)
        self.assertNotIn("private-address-marker", filtered.text)
        self.assertEqual(report.status_code, 200)
        self.assertIn(AuditAction.DOCUMENT_UPLOAD.value, report.text)
        self.assertIn("'=2+2", report.text)
        self.assertEqual(denied.status_code, 403)
        self.assertTrue(
            self.session.query(AuditEvent)
            .filter_by(actor_id=owner.id, action=AuditAction.ACCESS_DENIED.value)
            .count()
        )
