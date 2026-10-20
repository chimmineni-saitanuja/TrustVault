"""Test configuration and fixtures for TrustVault.

Provides isolated in-memory SQLite database sessions and FastAPI TestClient.
Compatible with both pytest and standard library unittest test runners.
"""

from collections.abc import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

from app.database import Base, get_db
from app.main import app

# Graceful pytest import to support environments where pytest has dependency collisions
try:
    import pytest
except Exception:
    pytest = None

# In-memory SQLite database with StaticPool to share connection across threads
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

test_engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestingSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=test_engine,
    expire_on_commit=False,
)


def get_test_db() -> Generator[Session, None, None]:
    """Test database dependency override."""
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


def setup_test_db():
    """Create all database schema tables."""
    Base.metadata.create_all(bind=test_engine)


def teardown_test_db():
    """Drop all database schema tables."""
    Base.metadata.drop_all(bind=test_engine)


if pytest is not None:
    @pytest.fixture(scope="session", autouse=True)
    def init_db():
        """Initialize database schema once per test session."""
        setup_test_db()
        yield
        teardown_test_db()

    @pytest.fixture()
    def db_session() -> Generator[Session, None, None]:
        """Provide a transactional database session rolled back after each test."""
        connection = test_engine.connect()
        transaction = connection.begin()
        session = TestingSessionLocal(bind=connection)

        yield session

        session.close()
        transaction.rollback()
        connection.close()

    @pytest.fixture()
    def client(db_session: Session) -> Generator[TestClient, None, None]:
        """FastAPI TestClient with overridden get_db dependency."""
        def _override_get_db():
            try:
                yield db_session
            finally:
                pass

        app.dependency_overrides[get_db] = _override_get_db
        with TestClient(app) as test_client:
            yield test_client
        app.dependency_overrides.clear()
