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
from app.models import AuditAction, AuditEvent, Document, User
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
        self.storage_path = Path(self.storage.name)

        def _override_get_db():
            yield self.session

        app.dependency_overrides[get_db] = _override_get_db
        self.client = TestClient(app)
        self.storage_setting = patch.object(settings, "STORAGE_DIR", self.storage.name)
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
