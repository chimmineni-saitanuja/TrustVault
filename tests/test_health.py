"""Tests for root and health-check endpoints.

Supports both pytest and standard library unittest test runners.
"""

import unittest
from unittest.mock import MagicMock
from starlette.testclient import TestClient

from app.database import Base, get_db
from app.main import app
from tests.conftest import setup_test_db, teardown_test_db, test_engine, TestingSessionLocal


class TestHealthEndpoints(unittest.TestCase):
    """Test suite for root and /health endpoints."""

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
            try:
                yield self.session
            finally:
                pass

        app.dependency_overrides[get_db] = _override_get_db
        self.client = TestClient(app)

    def tearDown(self):
        app.dependency_overrides.clear()
        self.session.close()
        self.transaction.rollback()
        self.connection.close()

    def test_root_endpoint_metadata(self):
        """Test GET / returns 200 and valid service metadata."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["service"], "TrustVault")
        self.assertEqual(data["status"], "operational")
        self.assertIn("version", data)
        self.assertIn("docs_url", data)
        self.assertIn("timestamp", data)

    def test_health_check_healthy(self):
        """Test GET /health returns 200 and reports database connected."""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["database"], "connected")
        self.assertIsNotNone(data["db_latency_ms"])
        self.assertGreaterEqual(data["db_latency_ms"], 0)

    def test_health_check_database_failure(self):
        """Test GET /health returns 503 and reports disconnected when DB probe fails."""
        mock_db = MagicMock()
        mock_db.execute.side_effect = Exception("Simulated connection timeout")

        def _broken_get_db():
            try:
                yield mock_db
            finally:
                pass

        app.dependency_overrides[get_db] = _broken_get_db
        try:
            response = self.client.get("/health")
            self.assertEqual(response.status_code, 503)
            data = response.json()
            self.assertEqual(data["status"], "unhealthy")
            self.assertEqual(data["database"], "disconnected")
            self.assertEqual(data["error"], "Database connectivity check failed")
            self.assertIsNone(data["db_latency_ms"])
        finally:
            app.dependency_overrides.clear()


# Pytest functional wrappers for pytest runners
def test_root_endpoint_pytest(client):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "TrustVault"
    assert data["status"] == "operational"


def test_health_endpoint_pytest(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"
