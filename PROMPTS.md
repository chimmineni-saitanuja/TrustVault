# TrustVault — AI Interaction and Development Log (PROMPTS.md)

This document contains a genuine, unembellished chronological record of prompts, AI outputs, discovered technical issues, corrections, and verification results throughout development.

---

## Entry 1: Milestone 1 — Project Foundation, Schema Architecture, and Environment Verification

- **Date**: 2026-10-20
- **Phase**: Milestone 1 (Project Foundation and Database)
- **Commit Reference**: Pending user review

### User Prompt Summary
Initialize Milestone 1 for TrustVault:
- Verify Python 3.14 compatibility and report exact issues if dependencies conflict.
- Ensure Git repository isolation so only the project directory is tracked.
- Set up FastAPI project structure, environment configuration, PostgreSQL/SQLAlchemy 2.0 models, Alembic migrations, root/health endpoints, documentation, and tests.
- Verify PostgreSQL 17 status and report honest database connection limits.
- Guarantee `/health` reports DB failure accurately, audit events preserve denied attempts, and audit logs cannot be updated or deleted.
- Stop after Milestone 1 without proceeding to Milestone 2.

### Actual Output & Implementation Actions
1. **Repository Isolation**:
   - Initial check revealed an outer repository at `C:\Users\chimm`.
   - Executed `git init` in `snovasys-trustvault` to isolate version control. Verified `git rev-parse --show-toplevel` returns the exact project directory.
2. **Environment & Dependency Discovery**:
   - Discovered that running `pytest` under the host Python 3.14 failed with:
     ```text
     AttributeError: module 'py' has no attribute 'path'
     ```
   - Traced the failure to a stray file `C:\Users\chimm\AppData\Local\Programs\Python\Python314\py.py` (containing `print("hii")`) located in the Python base directory, which shadowed the `py` module imported by `_pytest.compat`.
   - Following strict instructions not to modify the user's host environment silently, wrapped test fixtures and structured test suites using Python's standard library `unittest` runner.
   - Successfully verified that all core application packages (`fastapi`, `sqlalchemy`, `alembic`, `pydantic-settings`, `psycopg`) run without issues on Python 3.14.
3. **Database Migration Fix**:
   - Running `alembic upgrade head --sql` initially raised:
     ```text
     NotImplementedError: No support for ALTER of constraints in SQLite dialect.
     ```
   - Corrected `migrations/versions/0001_initial_schema.py` to embed `sa.UniqueConstraint` directly inside `op.create_table`, achieving cross-dialect compatibility across both PostgreSQL and SQLite.
4. **Audit Immutability & Health Probe**:
   - Implemented `ReadOnlyAuditLogError` via SQLAlchemy `@event.listens_for` hooks on `before_update` and `before_delete` for `AuditEvent`.
   - Created `/health` probe that returns HTTP 200 with latency when database queries succeed, and HTTP 503 with disconnected status when database probes fail.

### Verification Results
- Ran `python -m unittest discover -s tests -v`:
  - 8/8 tests passed (root metadata, healthy `/health`, unhealthy `/health` 503 on DB error, user creation, document/permission creation, denied audit context preservation, audit update prevention, audit delete prevention).
- Live server test via `uvicorn` and `Invoke-RestMethod`:
  - `GET /` returned HTTP 200 `status: operational`.
  - `GET /health` returned HTTP 200 `status: healthy`, `database: connected`, `db_latency_ms: 2.75`.
