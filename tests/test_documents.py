"""Tests for authenticated document uploads."""

import tempfile
import unittest
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from sqlalchemy.exc import SQLAlchemyError
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


class TestDocumentUploads(unittest.TestCase):
    """Exercise upload validation, storage, ownership, and persistence."""

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
        self.storage_path = Path(self.storage.name) / "private"
        self.storage_path.mkdir()

        def _override_get_db():
            yield self.session

        app.dependency_overrides[get_db] = _override_get_db
        self.client = TestClient(app)
        self.storage_setting = patch.object(settings, "STORAGE_DIR", str(self.storage_path))
        self.storage_setting.start()

    def tearDown(self):
        self.storage_setting.stop()
        app.dependency_overrides.clear()
        self.session.close()
        if self.transaction.is_active:
            self.transaction.rollback()
        self.connection.close()
        self.storage.cleanup()

    def _authorization(self, user: User) -> dict[str, str]:
        token = create_access_token(user.id)
        return {"Authorization": f"Bearer {token}"}

    def _make_document(self, owner: User, name: str) -> Document:
        document = Document(
            owner_id=owner.id,
            name=name,
            storage_path=f"generated-{name}.pdf",
            file_size=12,
            content_type="application/pdf",
        )
        self.session.add(document)
        self.session.commit()
        return document

    def _write_document_file(self, document: Document, content: bytes) -> Path:
        path = self.storage_path / document.storage_path
        path.write_bytes(content)
        return path

    def _grant(
        self,
        owner: User,
        document: Document,
        grantee: User,
        permission: str = "view",
        expires_at: datetime | None = None,
    ):
        return self.client.post(
            f"/documents/{document.id}/shares",
            headers=self._authorization(owner),
            json={
                "user_id": grantee.id,
                "permission": permission,
                "expires_at": expires_at.isoformat() if expires_at else None,
            },
        )

    def test_upload_stores_file_metadata_owner_and_audit(self):
        user = make_user(self.session, email="uploader@example.com")
        content = b"%PDF-1.7\nsafe sample"

        response = self.client.post(
            "/documents/upload",
            headers=self._authorization(user),
            files={"file": ("report.pdf", content, "application/pdf")},
        )

        self.assertEqual(response.status_code, 201)
        payload = response.json()
        self.assertEqual(payload["owner_id"], user.id)
        self.assertEqual(payload["name"], "report.pdf")
        self.assertEqual(payload["file_size"], len(content))
        self.assertEqual(payload["content_type"], "application/pdf")
        self.assertNotIn("sha256", payload)
        self.assertNotIn("storage_path", payload)

        document = self.session.query(Document).one()
        self.assertEqual(document.sha256, hashlib.sha256(content).hexdigest())
        stored_file = self.storage_path / document.storage_path
        self.assertTrue(stored_file.is_file())
        self.assertNotEqual(stored_file.name, "report.pdf")
        self.assertEqual(stored_file.read_bytes(), content)
        event = self.session.query(AuditEvent).one()
        self.assertEqual(event.action, AuditAction.DOCUMENT_UPLOAD)
        self.assertEqual(event.resource_id, document.id)
        self.assertEqual(event.actor_id, user.id)

    def test_tampered_file_is_not_served_and_records_safe_error_audit(self):
        owner = make_user(self.session, email="integrity-tamper-owner@example.com")
        document = self._make_document(owner, "tampered")
        original_content = b"%PDF-1.7\noriginal"
        self._write_document_file(document, original_content)
        document.sha256 = hashlib.sha256(original_content).hexdigest()
        self.session.commit()
        tampered_content = b"%PDF-1.7\ntampered"
        (self.storage_path / document.storage_path).write_bytes(tampered_content)

        for endpoint, action in (
            ("preview", AuditAction.DOCUMENT_READ),
            ("download", AuditAction.DOCUMENT_DOWNLOAD),
        ):
            response = self.client.get(
                f"/documents/{document.id}/{endpoint}",
                headers=self._authorization(owner),
            )
            self.assertEqual(response.status_code, 500)
            self.assertEqual(
                response.json()["detail"],
                "Document integrity verification failed",
            )
            self.assertNotIn(tampered_content, response.content)
            event = (
                self.session.query(AuditEvent)
                .filter_by(action=action, outcome="error")
                .one()
            )
            self.assertEqual(event.resource_id, document.id)
            self.assertNotIn(document.storage_path, event.reason)
            self.assertNotIn(tampered_content.decode(), event.reason)

    def test_legacy_document_gets_a_hash_on_first_authorized_access(self):
        owner = make_user(self.session, email="integrity-legacy-owner@example.com")
        document = self._make_document(owner, "legacy")
        content = b"%PDF-1.7\nlegacy content"
        self._write_document_file(document, content)
        self.assertIsNone(document.sha256)

        response = self.client.get(
            f"/documents/{document.id}/preview",
            headers=self._authorization(owner),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, content)
        self.assertEqual(document.sha256, hashlib.sha256(content).hexdigest())

    def test_unauthorized_request_does_not_backfill_legacy_document_hash(self):
        owner = make_user(self.session, email="integrity-private-owner@example.com")
        outsider = make_user(self.session, email="integrity-private-outsider@example.com")
        document = self._make_document(owner, "legacy-private")
        self._write_document_file(document, b"%PDF-1.7\nprivate")

        response = self.client.get(
            f"/documents/{document.id}/download",
            headers=self._authorization(outsider),
        )

        self.assertEqual(response.status_code, 404)
        self.assertIsNone(document.sha256)

    def test_upload_requires_authentication(self):
        response = self.client.post(
            "/documents/upload",
            files={"file": ("report.pdf", b"%PDF-1.7\nfile", "application/pdf")},
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(list(self.storage_path.iterdir()), [])

    def test_upload_rejects_invalid_names_and_file_types(self):
        user = make_user(self.session, email="invalid-upload@example.com")
        headers = self._authorization(user)

        invalid_name = self.client.post(
            "/documents/upload",
            headers=headers,
            files={"file": ("..\\outside.pdf", b"%PDF-1.7\nfile", "application/pdf")},
        )
        invalid_type = self.client.post(
            "/documents/upload",
            headers=headers,
            files={"file": ("report.pdf", b"not a PDF", "application/pdf")},
        )
        unsupported_type = self.client.post(
            "/documents/upload",
            headers=headers,
            files={"file": ("report.exe", b"payload", "application/octet-stream")},
        )

        self.assertEqual(invalid_name.status_code, 400)
        self.assertEqual(invalid_type.status_code, 400)
        self.assertEqual(unsupported_type.status_code, 415)
        self.assertEqual(self.session.query(Document).count(), 0)
        self.assertEqual(list(self.storage_path.iterdir()), [])

    def test_upload_rejects_files_over_configured_size_limit(self):
        user = make_user(self.session, email="large-upload@example.com")
        with patch.object(settings, "MAX_UPLOAD_SIZE_BYTES", 8):
            response = self.client.post(
                "/documents/upload",
                headers=self._authorization(user),
                files={"file": ("report.txt", b"123456789", "text/plain")},
            )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(self.session.query(Document).count(), 0)
        self.assertEqual(list(self.storage_path.iterdir()), [])

    def test_metadata_failure_rolls_back_and_removes_uploaded_file(self):
        user = make_user(self.session, email="rollback-upload@example.com")
        with patch.object(self.session, "commit", side_effect=SQLAlchemyError("database failure")):
            response = self.client.post(
                "/documents/upload",
                headers=self._authorization(user),
                files={"file": ("report.pdf", b"%PDF-1.7\nfile", "application/pdf")},
            )

        self.assertEqual(response.status_code, 500)
        self.assertIn("Check database migrations", response.json()["detail"])
        self.assertEqual(self.session.query(Document).count(), 0)
        self.assertEqual(self.session.query(AuditEvent).count(), 0)
        self.assertEqual(list(self.storage_path.iterdir()), [])

    def test_listing_returns_only_current_users_documents_without_storage_paths(self):
        owner = make_user(self.session, email="list-owner@example.com")
        other_owner = make_user(self.session, email="list-other@example.com")
        own_document = self._make_document(owner, "owned")
        self._make_document(other_owner, "other")

        response = self.client.get(
            "/documents/",
            headers=self._authorization(owner),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual([item["id"] for item in response.json()], [own_document.id])
        self.assertNotIn("storage_path", response.json()[0])
        self.assertNotIn("generated-owned.pdf", response.text)
        event = self.session.query(AuditEvent).one()
        self.assertEqual(event.action, AuditAction.DOCUMENT_READ)
        self.assertEqual(event.context_metadata["operation"], "list")

    def test_shared_listing_returns_only_active_grants_and_combines_permissions(self):
        owner = make_user(self.session, email="shared-list-owner@example.com")
        recipient = make_user(self.session, email="shared-list-recipient@example.com")
        outsider = make_user(self.session, email="shared-list-outsider@example.com")
        view_and_download = self._make_document(owner, "view-and-download")
        revoked = self._make_document(owner, "revoked")
        expired = self._make_document(owner, "expired")
        unshared = self._make_document(owner, "unshared")
        self.assertEqual(self._grant(owner, view_and_download, recipient, "view").status_code, 201)
        self.assertEqual(
            self._grant(owner, view_and_download, recipient, "download").status_code,
            201,
        )
        revoked_share = self._grant(owner, revoked, recipient, "view").json()
        self.assertEqual(
            self.client.delete(
                f"/documents/{revoked.id}/shares/{revoked_share['id']}",
                headers=self._authorization(owner),
            ).status_code,
            204,
        )
        self.session.add(
            DocumentPermission(
                document_id=expired.id,
                grantee_id=recipient.id,
                granted_by_id=owner.id,
                permission_level=PermissionLevel.VIEW,
                is_revoked=False,
                expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
            )
        )
        self.session.commit()
        self._grant(owner, unshared, outsider, "download")

        response = self.client.get(
            "/documents/shared-with-me",
            headers=self._authorization(recipient),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()), 1)
        shared = response.json()[0]
        self.assertEqual(shared["id"], view_and_download.id)
        self.assertEqual(shared["filename"], view_and_download.name)
        self.assertEqual(shared["owner_id"], owner.id)
        self.assertEqual(shared["owner_name"], owner.name)
        self.assertEqual(shared["owner_email"], owner.email)
        self.assertCountEqual(shared["permissions"], ["view", "download"])
        self.assertNotIn("storage_path", shared)
        self.assertNotIn(revoked.id, response.text)
        self.assertNotIn(expired.id, response.text)
        self.assertNotIn(unshared.id, response.text)
        event = (
            self.session.query(AuditEvent)
            .filter_by(action=AuditAction.DOCUMENT_READ)
            .one()
        )
        self.assertEqual(event.actor_id, recipient.id)
        self.assertEqual(event.context_metadata["operation"], "list_shared")

    def test_shared_listing_requires_authentication_and_hides_unshared_documents(self):
        owner = make_user(self.session, email="shared-auth-owner@example.com")
        recipient = make_user(self.session, email="shared-auth-recipient@example.com")
        document = self._make_document(owner, "not-shared")

        unauthenticated = self.client.get("/documents/shared-with-me")
        no_grants = self.client.get(
            "/documents/shared-with-me",
            headers=self._authorization(recipient),
        )

        self.assertEqual(unauthenticated.status_code, 401)
        self.assertEqual(no_grants.status_code, 200)
        self.assertEqual(no_grants.json(), [])
        self.assertNotIn(document.id, no_grants.text)

    def test_owner_can_view_document_metadata_without_storage_path(self):
        owner = make_user(self.session, email="details-owner@example.com")
        document = self._make_document(owner, "private")

        response = self.client.get(
            f"/documents/{document.id}",
            headers=self._authorization(owner),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["id"], document.id)
        self.assertEqual(response.json()["name"], "private")
        self.assertNotIn("storage_path", response.json())
        self.assertNotIn(document.storage_path, response.text)
        event = self.session.query(AuditEvent).one()
        self.assertEqual(event.action, AuditAction.DOCUMENT_READ)
        self.assertEqual(event.resource_id, document.id)

    def test_listing_and_details_require_authentication(self):
        document = self._make_document(
            make_user(self.session, email="auth-required-owner@example.com"),
            "restricted",
        )

        listing = self.client.get("/documents/")
        details = self.client.get(f"/documents/{document.id}")

        self.assertEqual(listing.status_code, 401)
        self.assertEqual(details.status_code, 401)

    def test_other_users_document_is_hidden_with_consistent_not_found(self):
        owner = make_user(self.session, email="private-owner@example.com")
        other_user = make_user(self.session, email="private-other@example.com")
        document = self._make_document(owner, "secret")
        headers = self._authorization(other_user)

        forbidden_document = self.client.get(
            f"/documents/{document.id}",
            headers=headers,
        )
        unknown_document = self.client.get(
            "/documents/nonexistent-document-id",
            headers=headers,
        )

        self.assertEqual(forbidden_document.status_code, 404)
        self.assertEqual(unknown_document.status_code, 404)
        self.assertEqual(forbidden_document.json(), unknown_document.json())
        self.assertEqual(forbidden_document.json()["detail"], "Document not found")
        self.assertEqual(
            self.session.query(AuditEvent).filter_by(outcome="denied").count(),
            2,
        )

    def test_owner_can_grant_view_and_download_permissions(self):
        owner = make_user(self.session, email="share-owner@example.com")
        grantee = make_user(self.session, email="share-recipient@example.com")
        document = self._make_document(owner, "shared")

        view_response = self._grant(owner, document, grantee, "view")
        download_response = self._grant(owner, document, grantee, "download")

        self.assertEqual(view_response.status_code, 201)
        self.assertEqual(view_response.json()["permission_level"], "view")
        self.assertEqual(view_response.json()["grantee_id"], grantee.id)
        self.assertEqual(download_response.status_code, 201)
        self.assertEqual(download_response.json()["permission_level"], "download")
        self.assertNotIn("storage_path", view_response.json())
        self.assertNotIn("password_hash", view_response.text)
        self.assertEqual(self.session.query(DocumentPermission).count(), 2)
        grant_events = (
            self.session.query(AuditEvent)
            .filter_by(action=AuditAction.PERMISSION_GRANT)
            .all()
        )
        self.assertEqual(len(grant_events), 2)

    def test_share_grant_rejects_missing_inactive_and_owner_recipients(self):
        owner = make_user(self.session, email="invalid-share-owner@example.com")
        inactive = make_user(self.session, email="inactive-recipient@example.com")
        inactive.is_active = False
        self.session.commit()
        document = self._make_document(owner, "restricted")

        missing = self.client.post(
            f"/documents/{document.id}/shares",
            headers=self._authorization(owner),
            json={"user_id": "missing-user", "permission": "view"},
        )
        inactive_response = self._grant(owner, document, inactive)
        owner_response = self._grant(owner, document, owner)

        self.assertEqual(missing.status_code, 404)
        self.assertEqual(inactive_response.status_code, 404)
        self.assertEqual(owner_response.status_code, 400)
        self.assertEqual(self.session.query(DocumentPermission).count(), 0)

    def test_share_grant_rejects_invalid_and_duplicate_permissions(self):
        owner = make_user(self.session, email="duplicate-share-owner@example.com")
        grantee = make_user(self.session, email="duplicate-share-recipient@example.com")
        document = self._make_document(owner, "duplicate")

        invalid = self._grant(owner, document, grantee, "edit")
        first = self._grant(owner, document, grantee)
        duplicate = self._grant(owner, document, grantee)

        self.assertEqual(invalid.status_code, 422)
        self.assertEqual(first.status_code, 201)
        self.assertEqual(duplicate.status_code, 409)
        self.assertEqual(self.session.query(DocumentPermission).count(), 1)

    def test_share_expiration_must_be_timezone_aware_and_in_the_future(self):
        owner = make_user(self.session, email="expiration-validation-owner@example.com")
        recipient = make_user(self.session, email="expiration-validation-recipient@example.com")
        document = self._make_document(owner, "expiration-validation")

        naive_expiration = datetime.now() + timedelta(hours=1)
        past_expiration = datetime.now(timezone.utc) - timedelta(minutes=1)
        naive = self._grant(owner, document, recipient, expires_at=naive_expiration)
        past = self._grant(owner, document, recipient, expires_at=past_expiration)

        self.assertEqual(naive.status_code, 422)
        self.assertEqual(past.status_code, 422)
        self.assertEqual(self.session.query(DocumentPermission).count(), 0)

    def test_expired_grant_can_be_reactivated_with_a_new_expiration(self):
        owner = make_user(self.session, email="expiration-regrant-owner@example.com")
        recipient = make_user(self.session, email="expiration-regrant-recipient@example.com")
        document = self._make_document(owner, "expiration-regrant")
        old_grant = DocumentPermission(
            document_id=document.id,
            grantee_id=recipient.id,
            granted_by_id=owner.id,
            permission_level=PermissionLevel.VIEW,
            is_revoked=False,
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        )
        self.session.add(old_grant)
        self.session.commit()
        new_expiration = datetime.now(timezone.utc) + timedelta(hours=1)

        regrant = self._grant(owner, document, recipient, expires_at=new_expiration)

        self.assertEqual(regrant.status_code, 201)
        self.assertEqual(regrant.json()["id"], old_grant.id)
        self.assertFalse(regrant.json()["is_revoked"])
        self.assertIsNotNone(regrant.json()["expires_at"])
        self.assertEqual(self.session.query(DocumentPermission).count(), 1)

    def test_non_owner_cannot_grant_list_or_revoke_shares(self):
        owner = make_user(self.session, email="authorize-share-owner@example.com")
        other_user = make_user(self.session, email="authorize-share-other@example.com")
        recipient = make_user(self.session, email="authorize-share-recipient@example.com")
        document = self._make_document(owner, "owner-only")
        share = self._grant(owner, document, recipient).json()
        headers = self._authorization(other_user)

        grant = self.client.post(
            f"/documents/{document.id}/shares",
            headers=headers,
            json={"user_id": other_user.id, "permission": "view"},
        )
        listing = self.client.get(f"/documents/{document.id}/shares", headers=headers)
        revoke = self.client.delete(
            f"/documents/{document.id}/shares/{share['id']}",
            headers=headers,
        )

        self.assertEqual(grant.status_code, 404)
        self.assertEqual(listing.status_code, 404)
        self.assertEqual(revoke.status_code, 404)
        self.assertFalse(self.session.query(DocumentPermission).one().is_revoked)

    def test_owner_can_list_shares_and_admin_can_manage_them(self):
        owner = make_user(self.session, email="list-shares-owner@example.com")
        admin = make_user(
            self.session,
            email="list-shares-admin@example.com",
            role=UserRole.ADMIN,
        )
        recipient = make_user(self.session, email="list-shares-recipient@example.com")
        admin_recipient = make_user(self.session, email="admin-share-recipient@example.com")
        document = self._make_document(owner, "listed")
        self.assertEqual(self._grant(owner, document, recipient).status_code, 201)

        owner_list = self.client.get(
            f"/documents/{document.id}/shares",
            headers=self._authorization(owner),
        )
        admin_list = self.client.get(
            f"/documents/{document.id}/shares",
            headers=self._authorization(admin),
        )
        admin_grant = self._grant(admin, document, admin_recipient)

        self.assertEqual(owner_list.status_code, 200)
        self.assertEqual(len(owner_list.json()), 1)
        self.assertEqual(admin_list.status_code, 200)
        self.assertEqual(admin_grant.status_code, 201)
        admin_revoke = self.client.delete(
            f"/documents/{document.id}/shares/{admin_grant.json()['id']}",
            headers=self._authorization(admin),
        )
        self.assertEqual(admin_revoke.status_code, 204)

    def test_revoked_permission_can_be_granted_again_without_duplicate_rows(self):
        owner = make_user(self.session, email="regrant-owner@example.com")
        recipient = make_user(self.session, email="regrant-recipient@example.com")
        document = self._make_document(owner, "regrant")
        first = self._grant(owner, document, recipient)
        share_id = first.json()["id"]
        revoked = self.client.delete(
            f"/documents/{document.id}/shares/{share_id}",
            headers=self._authorization(owner),
        )

        regrant = self._grant(owner, document, recipient)

        self.assertEqual(revoked.status_code, 204)
        self.assertEqual(regrant.status_code, 201)
        self.assertEqual(regrant.json()["id"], share_id)
        self.assertFalse(regrant.json()["is_revoked"])
        self.assertEqual(self.session.query(DocumentPermission).count(), 1)

    def test_owner_can_revoke_share_and_audit_it(self):
        owner = make_user(self.session, email="revoke-owner@example.com")
        recipient = make_user(self.session, email="revoke-recipient@example.com")
        document = self._make_document(owner, "revoke")
        share = self._grant(owner, document, recipient).json()

        response = self.client.delete(
            f"/documents/{document.id}/shares/{share['id']}",
            headers=self._authorization(owner),
        )

        self.assertEqual(response.status_code, 204)
        persisted_share = self.session.query(DocumentPermission).one()
        self.assertTrue(persisted_share.is_revoked)
        self.assertIsNotNone(persisted_share.revoked_at)
        event = (
            self.session.query(AuditEvent)
            .filter_by(action=AuditAction.PERMISSION_REVOKE)
            .one()
        )
        self.assertEqual(event.resource_id, document.id)
        self.assertEqual(event.context_metadata["share_id"], share["id"])

        repeated = self.client.delete(
            f"/documents/{document.id}/shares/{share['id']}",
            headers=self._authorization(owner),
        )
        self.assertEqual(repeated.status_code, 409)

    def test_grant_audit_failure_rolls_back_share(self):
        owner = make_user(self.session, email="grant-failure-owner@example.com")
        recipient = make_user(self.session, email="grant-failure-recipient@example.com")
        document = self._make_document(owner, "grant-failure")

        with patch.object(self.session, "commit", side_effect=SQLAlchemyError("database failure")):
            response = self._grant(owner, document, recipient)

        self.assertEqual(response.status_code, 500)
        self.assertEqual(self.session.query(DocumentPermission).count(), 0)
        self.assertEqual(self.session.query(AuditEvent).count(), 0)

    def test_revoke_audit_failure_rolls_back_revocation(self):
        owner = make_user(self.session, email="revoke-failure-owner@example.com")
        recipient = make_user(self.session, email="revoke-failure-recipient@example.com")
        document = self._make_document(owner, "revoke-failure")
        share = self._grant(owner, document, recipient).json()

        self.session.close()
        self.session = TestingSessionLocal(
            bind=self.connection,
            join_transaction_mode="create_savepoint",
        )
        with (
            patch.object(self.session, "commit", side_effect=SQLAlchemyError("database failure")),
            patch.object(self.session, "rollback", wraps=self.session.rollback) as rollback,
        ):
            response = self.client.delete(
                f"/documents/{document.id}/shares/{share['id']}",
                headers=self._authorization(owner),
            )

        self.assertEqual(response.status_code, 500)
        rollback.assert_called_once()
        self.assertFalse(self.session.query(DocumentPermission).one().is_revoked)
        self.assertEqual(self.session.query(AuditEvent).filter_by(
            action=AuditAction.PERMISSION_REVOKE
        ).count(), 0)

    def test_owner_can_download_document_and_success_is_audited(self):
        owner = make_user(self.session, email="download-owner@example.com")
        document = self._make_document(owner, "owner-download")
        content = b"private owner document"
        stored_path = self._write_document_file(document, content)

        response = self.client.get(
            f"/documents/{document.id}/download",
            headers=self._authorization(owner),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, content)
        self.assertIn('filename="owner-download"', response.headers["content-disposition"])
        self.assertNotIn(str(stored_path), response.text)
        self.assertNotIn(document.storage_path, response.headers["content-disposition"])
        event = (
            self.session.query(AuditEvent)
            .filter_by(action=AuditAction.DOCUMENT_DOWNLOAD)
            .one()
        )
        self.assertEqual(event.outcome.value, "success")
        self.assertEqual(event.resource_id, document.id)
        self.assertNotIn(content.decode(), str(event.context_metadata))

    def test_owner_and_active_view_or_download_grants_can_preview_inline(self):
        owner = make_user(self.session, email="preview-owner@example.com")
        viewer = make_user(self.session, email="preview-viewer@example.com")
        downloader = make_user(self.session, email="preview-downloader@example.com")
        document = self._make_document(owner, "previewable")
        content = b"%PDF-1.7\npreview content"
        self._write_document_file(document, content)
        self.assertEqual(self._grant(owner, document, viewer, "view").status_code, 201)
        self.assertEqual(self._grant(owner, document, downloader, "download").status_code, 201)

        owner_response = self.client.get(
            f"/documents/{document.id}/preview",
            headers=self._authorization(owner),
        )
        viewer_response = self.client.get(
            f"/documents/{document.id}/preview",
            headers=self._authorization(viewer),
        )
        downloader_response = self.client.get(
            f"/documents/{document.id}/preview",
            headers=self._authorization(downloader),
        )

        for response in (owner_response, viewer_response, downloader_response):
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, content)
            self.assertTrue(response.headers["content-disposition"].startswith("inline;"))
            self.assertEqual(response.headers["x-content-type-options"], "nosniff")
            self.assertNotIn(document.storage_path, response.headers["content-disposition"])
        self.assertEqual(
            self.session.query(AuditEvent)
            .filter_by(action=AuditAction.DOCUMENT_READ, resource_id=document.id)
            .count(),
            3,
        )

    def test_unshared_user_cannot_preview_document(self):
        owner = make_user(self.session, email="preview-unshared-owner@example.com")
        unrelated = make_user(self.session, email="preview-unshared-user@example.com")
        document = self._make_document(owner, "private-preview")
        self._write_document_file(document, b"private")

        response = self.client.get(
            f"/documents/{document.id}/preview",
            headers=self._authorization(unrelated),
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["detail"], "Document not found")
        event = self.session.query(AuditEvent).filter_by(
            action=AuditAction.ACCESS_DENIED
        ).one()
        self.assertEqual(event.actor_id, unrelated.id)

    def test_owner_cannot_preview_pending_or_rejected_documents(self):
        owner = make_user(self.session, email="preview-unapproved-owner@example.com")

        for review_status in (
            DocumentReviewStatus.PENDING,
            DocumentReviewStatus.REJECTED,
        ):
            document = self._make_document(owner, f"unapproved-{review_status.value}")
            document.review_status = review_status
            self.session.commit()
            self._write_document_file(document, b"not approved")

            response = self.client.get(
                f"/documents/{document.id}/preview",
                headers=self._authorization(owner),
            )

            self.assertEqual(response.status_code, 404)
            self.assertEqual(response.json()["detail"], "Document not found")

        denied_events = (
            self.session.query(AuditEvent)
            .filter_by(action=AuditAction.ACCESS_DENIED, actor_id=owner.id)
            .all()
        )
        self.assertEqual(len(denied_events), 2)
        self.assertTrue(
            all(event.outcome.value == "denied" for event in denied_events)
        )

    def test_revoked_view_grant_cannot_preview_document(self):
        owner = make_user(self.session, email="preview-revoked-owner@example.com")
        recipient = make_user(self.session, email="preview-revoked-user@example.com")
        document = self._make_document(owner, "revoked-preview")
        self._write_document_file(document, b"revoked")
        for permission in ("view", "download"):
            share = self._grant(owner, document, recipient, permission).json()
            self.assertEqual(
                self.client.delete(
                    f"/documents/{document.id}/shares/{share['id']}",
                    headers=self._authorization(owner),
                ).status_code,
                204,
            )

        preview = self.client.get(
            f"/documents/{document.id}/preview",
            headers=self._authorization(recipient),
        )
        download = self.client.get(
            f"/documents/{document.id}/download",
            headers=self._authorization(recipient),
        )

        self.assertEqual(preview.status_code, 404)
        self.assertEqual(download.status_code, 404)
        self.assertEqual(preview.json()["detail"], "Document not found")
        self.assertEqual(download.json()["detail"], "Document not found")

    def test_expired_download_grant_cannot_preview_or_download_and_is_not_listed(self):
        owner = make_user(self.session, email="expiration-expired-owner@example.com")
        recipient = make_user(self.session, email="expiration-expired-recipient@example.com")
        document = self._make_document(owner, "expired-download")
        self._write_document_file(document, b"expired")
        self.session.add(
            DocumentPermission(
                document_id=document.id,
                grantee_id=recipient.id,
                granted_by_id=owner.id,
                permission_level=PermissionLevel.DOWNLOAD,
                is_revoked=False,
                expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
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

    def test_active_expiring_and_non_expiring_grants_allow_only_their_permissions(self):
        owner = make_user(self.session, email="expiration-active-owner@example.com")
        expiring_downloader = make_user(self.session, email="expiration-active-recipient@example.com")
        non_expiring_viewer = make_user(self.session, email="non-expiring-recipient@example.com")
        document = self._make_document(owner, "active-expiration")
        content = b"authorized document"
        self._write_document_file(document, content)
        expiration = datetime.now(timezone.utc) + timedelta(hours=1)

        expiring_grant = self._grant(
            owner,
            document,
            expiring_downloader,
            "download",
            expiration,
        )
        non_expiring_grant = self._grant(owner, document, non_expiring_viewer, "view")

        self.assertEqual(expiring_grant.status_code, 201)
        self.assertIsNotNone(expiring_grant.json()["expires_at"])
        self.assertEqual(non_expiring_grant.status_code, 201)
        self.assertIsNone(non_expiring_grant.json()["expires_at"])
        for user in (expiring_downloader, non_expiring_viewer):
            preview = self.client.get(
                f"/documents/{document.id}/preview",
                headers=self._authorization(user),
            )
            self.assertEqual(preview.status_code, 200)
            self.assertEqual(preview.content, content)
        allowed_download = self.client.get(
            f"/documents/{document.id}/download",
            headers=self._authorization(expiring_downloader),
        )
        denied_download = self.client.get(
            f"/documents/{document.id}/download",
            headers=self._authorization(non_expiring_viewer),
        )
        self.assertEqual(allowed_download.status_code, 200)
        self.assertEqual(allowed_download.content, content)
        self.assertEqual(denied_download.status_code, 404)

    def test_preview_requires_view_or_download_permission(self):
        owner = make_user(self.session, email="preview-limited-owner@example.com")
        recipient = make_user(self.session, email="preview-limited-user@example.com")
        document = self._make_document(owner, "limited-preview")
        self._write_document_file(document, b"limited")
        self.session.add(
            DocumentPermission(
                document_id=document.id,
                grantee_id=recipient.id,
                granted_by_id=owner.id,
                permission_level=PermissionLevel.READ,
                is_revoked=False,
            )
        )
        self.session.commit()

        response = self.client.get(
            f"/documents/{document.id}/preview",
            headers=self._authorization(recipient),
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["detail"], "Document not found")

    def test_active_download_share_allows_download_and_view_share_does_not(self):
        owner = make_user(self.session, email="permission-download-owner@example.com")
        downloader = make_user(self.session, email="download-authorized@example.com")
        viewer = make_user(self.session, email="download-viewer@example.com")
        document = self._make_document(owner, "shared-download")
        content = b"shared file body"
        self._write_document_file(document, content)
        self.assertEqual(self._grant(owner, document, downloader, "download").status_code, 201)
        self.assertEqual(self._grant(owner, document, viewer, "view").status_code, 201)

        permitted = self.client.get(
            f"/documents/{document.id}/download",
            headers=self._authorization(downloader),
        )
        view_denied = self.client.get(
            f"/documents/{document.id}/download",
            headers=self._authorization(viewer),
        )

        self.assertEqual(permitted.status_code, 200)
        self.assertEqual(permitted.content, content)
        self.assertEqual(view_denied.status_code, 404)
        self.assertEqual(view_denied.json()["detail"], "Document not found")
        denied_event = (
            self.session.query(AuditEvent)
            .filter_by(action=AuditAction.ACCESS_DENIED)
            .one()
        )
        self.assertEqual(denied_event.outcome.value, "denied")
        self.assertEqual(denied_event.actor_id, viewer.id)

    def test_unrelated_user_and_admin_without_share_cannot_download(self):
        owner = make_user(self.session, email="unrelated-download-owner@example.com")
        unrelated = make_user(self.session, email="unrelated-downloader@example.com")
        admin = make_user(
            self.session,
            email="unshared-download-admin@example.com",
            role=UserRole.ADMIN,
        )
        document = self._make_document(owner, "unrelated")
        self._write_document_file(document, b"restricted")

        unrelated_response = self.client.get(
            f"/documents/{document.id}/download",
            headers=self._authorization(unrelated),
        )
        admin_response = self.client.get(
            f"/documents/{document.id}/download",
            headers=self._authorization(admin),
        )

        self.assertEqual(unrelated_response.status_code, 404)
        self.assertEqual(admin_response.status_code, 404)
        self.assertEqual(unrelated_response.json(), admin_response.json())
        self.assertEqual(
            self.session.query(AuditEvent)
            .filter_by(action=AuditAction.ACCESS_DENIED)
            .count(),
            2,
        )

    def test_download_requires_authentication_and_hides_unknown_documents(self):
        response = self.client.get("/documents/unknown-document/download")

        self.assertEqual(response.status_code, 401)
        self.assertNotIn("storage_path", response.text)

        owner = make_user(self.session, email="unknown-download-owner@example.com")
        unknown = self.client.get(
            "/documents/unknown-document/download",
            headers=self._authorization(owner),
        )
        self.assertEqual(unknown.status_code, 404)
        self.assertEqual(unknown.json()["detail"], "Document not found")
        self.assertEqual(
            self.session.query(AuditEvent)
            .filter_by(action=AuditAction.ACCESS_DENIED)
            .count(),
            1,
        )

    def test_missing_stored_file_returns_safe_not_found_and_audits_error(self):
        owner = make_user(self.session, email="missing-download-owner@example.com")
        document = self._make_document(owner, "missing-file")

        response = self.client.get(
            f"/documents/{document.id}/download",
            headers=self._authorization(owner),
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["detail"], "Document file not found")
        self.assertNotIn(document.storage_path, response.text)
        event = (
            self.session.query(AuditEvent)
            .filter_by(action=AuditAction.DOCUMENT_DOWNLOAD)
            .one()
        )
        self.assertEqual(event.outcome.value, "error")
        self.assertNotIn(document.storage_path, event.reason)

    def test_download_rejects_storage_paths_outside_private_directory(self):
        owner = make_user(self.session, email="traversal-download-owner@example.com")
        document = self._make_document(owner, "traversal")
        document.storage_path = "..\\outside.pdf"
        self.session.commit()
        outside_file = Path(self.storage.name) / "outside.pdf"
        outside_file.write_bytes(b"must not be served")

        response = self.client.get(
            f"/documents/{document.id}/download",
            headers=self._authorization(owner),
        )

        self.assertEqual(response.status_code, 404)
        self.assertNotIn("must not be served", response.text)
        self.assertEqual(
            self.session.query(AuditEvent)
            .filter_by(action=AuditAction.DOCUMENT_DOWNLOAD)
            .one()
            .outcome.value,
            "error",
        )

    def test_download_audit_failure_does_not_return_file(self):
        owner = make_user(self.session, email="audit-download-owner@example.com")
        document = self._make_document(owner, "audit-failure")
        self._write_document_file(document, b"must not be returned")

        with (
            patch.object(self.session, "commit", side_effect=SQLAlchemyError("database failure")),
            patch.object(self.session, "rollback", wraps=self.session.rollback) as rollback,
        ):
            response = self.client.get(
                f"/documents/{document.id}/download",
                headers=self._authorization(owner),
            )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()["detail"], "Document request failed")
        self.assertNotIn("must not be returned", response.text)
        rollback.assert_called_once()
