# TrustVault

> **Secure document sharing with a real audit trail.**

TrustVault is a secure, enterprise-grade document sharing system designed to enforce document-level permissions, guarantee immediate access revocation, and preserve an immutable, tamper-resistant audit trail.

---

## Project Status

| Milestone | Scope | Status |
| :--- | :--- | :--- |
| **Milestone 1** | **Project Foundation and Database** | **Completed** |
| Milestone 2 | Authentication and Authorization | Implemented; pending review |
| Milestone 3 | Document Management, Sharing and Audit | Upload foundation implemented; sharing and downloads pending |
| Milestone 4 | Frontend and Integration | Pending Review |
| Milestone 5 | Security Verification, Deployment and Submission | Pending Review |

---

## Architecture & Technology Stack

- **Backend**: Python with FastAPI
- **Database**: PostgreSQL 17 (production/dev) with in-memory SQLite support for fast test isolation
- **ORM**: SQLAlchemy 2.0 (strict type annotations, session lifecycle management)
- **Migrations**: Alembic (version-controlled, reproducible migrations)
- **Authentication**: Argon2id password hashing and HS256-signed JWT access tokens
- **Audit Security**: Append-only audit model with ORM-level event listeners preventing modification or deletion
- **Testing**: Python `unittest` test suite and Pytest-compatible fixtures

---

## Directory Structure

```text
trustvault/
├── app/
│   ├── __init__.py           # Package version and metadata
│   ├── config.py             # Pydantic BaseSettings environment configuration
│   ├── database.py           # SQLAlchemy 2.0 engine, SessionLocal, get_db lifecycle
│   ├── main.py               # FastAPI entry point, root and /health endpoints
│   ├── models.py             # Users, Documents, Permissions, and AuditEvent models
│   ├── dependencies.py       # Active-user authentication and role checks
│   ├── routers/
│   │   ├── auth.py           # Registration, login, and current-user profile
│   │   ├── documents.py      # Authenticated document upload
│   │   └── users.py          # Admin-only user listing
│   └── schemas/
│       ├── auth.py           # Authentication request and public response schemas
│       └── documents.py      # Public document upload metadata
├── migrations/
│   ├── env.py                # Alembic migration runner
│   ├── script.py.mako        # Migration template
│   └── versions/
│       └── 0001_initial_schema.py # Initial database migration
├── tests/
│   ├── __init__.py
│   ├── conftest.py           # In-memory SQLite fixtures and TestClient overrides
│   ├── test_documents.py     # Document upload, validation, ownership, and rollback tests
│   ├── test_health.py        # Root and live/failed /health endpoint tests
│   └── test_models.py        # Model validation, denied-audit context, immutability tests
├── .env.example              # Environment variables template
├── .gitignore                # Git ignore rules
├── alembic.ini               # Alembic configuration
├── requirements.txt          # Pinned project dependencies
├── README.md                 # Setup, architecture, and operation guide
├── THREATS.md                # Threat model and security mitigations
└── PROMPTS.md                # Genuine development and AI interaction log
```

---

## Setup and Installation

### 1. Prerequisites
- Python 3.13 or 3.14
- PostgreSQL 17 (running locally or remotely)
- Git

> [!NOTE]
> **Python 3.14 Notice**: Python 3.14 is supported for core application packages (`fastapi`, `sqlalchemy`, `alembic`, `psycopg`). If your Python installation has a stray `py.py` module in the Python home directory shadowing the legacy `py` package, use the standard library test runner (`python -m unittest discover -s tests`) or Python 3.13.

### 2. Virtual Environment Setup

```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Environment Configuration

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Edit `.env` to configure your PostgreSQL credentials:

```dotenv
DATABASE_URL=postgresql+psycopg://postgres:your_password@localhost:5432/trustvault_dev
SECRET_KEY=generate-a-secure-random-32-byte-hex-string
```

*Note: If no PostgreSQL credentials are configured, the application falls back to `sqlite:///./trustvault_local.db` for local testing.*

### 4. Database Migrations

Run database migrations to initialize tables and indexes:

```bash
# Review SQL without applying (offline mode)
alembic upgrade head --sql

# Apply migrations to configured database
alembic upgrade head
```

### 5. Running the Application

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

- **Interactive API Documentation (Swagger)**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Root Metadata**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **System Health Check**: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

---

### Authentication and Authorization

- `POST /auth/register` creates a viewer account; passwords are hashed with Argon2id.
- `POST /auth/login` returns an HS256-signed JWT access token. Failed attempts are audited and return a generic `401` message.
- `GET /auth/me` returns the authenticated active user's public profile.
- `GET /users/` lists users for admins only; other authenticated roles receive `403`.

Registration and its audit event are committed atomically. Login audit persistence must succeed before a success or failure response is returned. Public profiles never include password hashes.

### Document Upload Foundation

- `POST /documents/upload` requires a valid bearer token and records the authenticated user as the document owner.
- Uploads accept PDF, PNG, JPEG, and UTF-8 text files with matching filename extensions and media types. Binary file signatures are checked.
- Files are streamed to `STORAGE_DIR` (default: `storage/documents`) under generated names. The original name is stored only as document metadata; the storage path is not returned by the API.
- Upload size is capped by `MAX_UPLOAD_SIZE_BYTES` (default: 10 MiB). If database or audit persistence fails, the transaction is rolled back and the stored file is removed.
- `GET /documents/` lists only the authenticated user's documents, and `GET /documents/{document_id}` returns metadata only for a document that user owns. Missing and other users' document IDs both return `404`.
- Successful reads and denied detail lookups are audited. API responses never include internal storage paths or generated storage names.
- Document owners and admins can manage shares with `POST /documents/{document_id}/shares`, `GET /documents/{document_id}/shares`, and `DELETE /documents/{document_id}/shares/{share_id}`. Grants support `view` and `download` permissions for existing active users; duplicate active grants are rejected, and revoked grants can be reactivated.
- Share grants and revocations are recorded atomically with the permission change. Share-management responses contain recipient identity and permission metadata only, not storage details or password hashes. The download permission is recorded but no download endpoint is implemented.
- Keep `STORAGE_DIR` outside any public/static web root. Sharing metadata is managed through the endpoints above, but the application does not expose a file download endpoint yet.

## Running Automated Tests

Run the full test suite, including health checks, model constraints, audit immutability, authentication, document upload, sharing and revocation, audit behavior, and role enforcement:

```bash
python -m pytest -v
```

Tests use an isolated in-memory SQLite database, so they do not modify the configured development or production database.
