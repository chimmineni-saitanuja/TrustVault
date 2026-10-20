# TrustVault

> **Secure document sharing with a real audit trail.**

TrustVault is a secure, enterprise-grade document sharing system designed to enforce document-level permissions, guarantee immediate access revocation, and preserve an immutable, tamper-resistant audit trail.

---

## Project Status

| Milestone | Scope | Status |
| :--- | :--- | :--- |
| **Milestone 1** | **Project Foundation and Database** | **Completed** |
| Milestone 2 | Authentication and Authorization | Pending Review |
| Milestone 3 | Document Management, Sharing and Audit | Pending Review |
| Milestone 4 | Frontend and Integration | Pending Review |
| Milestone 5 | Security Verification, Deployment and Submission | Pending Review |

---

## Architecture & Technology Stack

- **Backend**: Python with FastAPI
- **Database**: PostgreSQL 17 (production/dev) with in-memory SQLite support for fast test isolation
- **ORM**: SQLAlchemy 2.0 (strict type annotations, session lifecycle management)
- **Migrations**: Alembic (version-controlled, reproducible migrations)
- **Authentication**: Argon2 password hashing & signed JWT tokens (configured for Milestone 2)
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
│   └── models.py             # Users, Documents, Permissions, and AuditEvent models
├── migrations/
│   ├── env.py                # Alembic migration runner
│   ├── script.py.mako        # Migration template
│   └── versions/
│       └── 0001_initial_schema.py # Initial database migration
├── tests/
│   ├── __init__.py
│   ├── conftest.py           # In-memory SQLite fixtures and TestClient overrides
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

## Running Automated Tests

Run the full test suite verifying endpoints, model constraints, denied audit recording, and audit immutability:

```bash
python -m unittest discover -s tests -v
```

All 8 automated tests run against an isolated in-memory SQLite database (`StaticPool`), ensuring zero contamination of production or development data.
