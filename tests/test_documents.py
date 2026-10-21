"""Tests for authenticated document uploads."""

import tempfile
import unittest
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

    def _grant(self, owner: User, document: Document, grantee: User, permission: str = "view"):
        return self.client.post(
            f"/documents/{document.id}/shares",
            headers=self._authorization(owner),
            json={"user_id": grantee.id, "permission": permission},
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
        self.assertNotIn("storage_path", payload)

        document = self.session.query(Document).one()
        stored_file = self.storage_path / document.storage_path
        self.assertTrue(stored_file.is_file())
        self.assertNotEqual(stored_file.name, "report.pdf")
        self.assertEqual(stored_file.read_bytes(), content)
        event = self.session.query(AuditEvent).one()
        self.assertEqual(event.action, AuditAction.DOCUMENT_UPLOAD)
        self.assertEqual(event.resource_id, document.id)
        self.assertEqual(event.actor_id, user.id)

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
