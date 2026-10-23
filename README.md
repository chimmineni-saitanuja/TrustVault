# TrustVault

TrustVault is a document workspace for private file storage and permission-based sharing. The FastAPI backend owns authentication, authorization, file access, and audit decisions; a React frontend provides the user interface.

## 1. Project Overview and Key Features

- Register and sign in with bearer-token authentication.
- Upload PDF, PNG, JPEG, or text documents to a private storage directory.
- Manage document-level `view` and `download` grants, including optional expirations and revocation.
- Browse documents shared with the current user, preview authorized files, and download only when explicitly permitted.
- Review recent actor-scoped events in the Activity Log; security-sensitive operations are recorded in an application-level append-only audit log.
- Bootstrap an administrator privately, review uploaded documents, and approve or reject them with a reason.
- Use the Admin dashboard for user/document/review totals, all-owner document search, account activation controls, permission-grant revocation, filtered audit events, and CSV audit/review-history exports.

## 2. Frontend

The frontend is a React 18 and TypeScript single-page application built with Vite. It supports account registration and login, owned-document search and upload, share management, a separate **Shared with me** list, inline previews, permission-gated downloads, and an actor-scoped **Activity Log**. Administrators also have an overview, searchable document catalog, review queue, account activation controls, global permission revocation, an audit center, and filtered CSV exports. The bearer token is kept in browser `sessionStorage`; the default API URL is `http://127.0.0.1:8000` and can be overridden with `VITE_API_BASE_URL`.

## 3. Backend API

FastAPI exposes interactive API documentation at `/docs`. Protected endpoints require a bearer token.

| Area | Endpoints |
| --- | --- |
| Service | `GET /`, `GET /health` |
| Authentication | `POST /auth/register`, `POST /auth/login`, `GET /auth/me` |
| Users | `GET /users/` (admin only) |
| Activity | `GET /activity/` (authenticated, actor-scoped) |
| Administration | `GET /admin/dashboard`, `GET /admin/documents`, `GET /admin/documents/{document_id}/preview`, `POST /admin/documents/{document_id}/approve`, `POST /admin/documents/{document_id}/reject`, `POST /admin/users/{user_id}/deactivate`, `POST /admin/users/{user_id}/reactivate`, `GET /admin/permissions`, `DELETE /admin/permissions/{permission_id}`, `GET /admin/audit`, `GET /admin/reports/export` (admin only) |
| Documents | `POST /documents/upload`, `GET /documents/`, `GET /documents/{document_id}` |
| Sharing | `POST /documents/{document_id}/shares`, `GET /documents/{document_id}/shares`, `DELETE /documents/{document_id}/shares/{share_id}` |
| Shared access | `GET /documents/shared-with-me`, `GET /documents/{document_id}/preview`, `GET /documents/{document_id}/download` |

## 4. Database and Migrations

SQLAlchemy 2.x models users, documents, document permissions, and audit events. The configured database defaults to local SQLite (`sqlite:///./trustvault_local.db`); PostgreSQL is supported through the `psycopg` v3 driver. Alembic migrations are under `migrations/`; apply them with `alembic upgrade head`.

## 5. Authentication and Authorization

Passwords are hashed with Argon2id. Login issues an HS256-signed JWT whose subject identifies the user; each protected request resolves that subject to an active database account. Registration assigns the `viewer` role. Admin-only user listing, account status changes, document review, audit/report access, and permission revocation are enforced by backend dependencies and route checks. Account status changes and denied role checks are audited; the last active Admin cannot be deactivated.

Document ownership and grants are separate: owners can manage shares; recipients need an active, non-revoked, non-expired `view` or `download` grant to preview, and an active `download` grant to download. Grants may optionally expire at a timezone-aware timestamp, normalized to UTC; grants without an expiration remain active until revoked. New uploads await administrator review; file access and sharing are blocked until approval. Existing documents migrate as approved. Admin review previews are protected and audited; Admin status alone does not grant access to another user's file through normal document routes. Public user and document responses omit password hashes and storage paths. Admin audit responses expose only safe actor/action/outcome/time/document labels; they do not include request metadata, addresses, or storage details.

## 6. Secure File Storage and Document Sharing

Uploads are streamed under generated filenames to `STORAGE_DIR` (default `storage/documents`), outside the public web root. The API validates the supported file type and signature where applicable and limits uploads with `MAX_UPLOAD_SIZE_BYTES` (default 10 MiB). SHA-256 is calculated while receiving each upload and stored with its metadata. Before serving an authorized file, the backend resolves its path inside private storage and verifies the digest in chunks; a mismatch blocks the response and records an error audit event without recording the path or file contents.

The digest column is nullable for compatibility with existing documents. Their first authorized preview or download calculates and stores a baseline digest before serving. This trust-on-first-use step protects subsequent requests but cannot establish that a legacy file was not altered before its baseline was recorded. Where historical integrity matters, verify legacy files against a trusted backup or other trusted source before allowing their first access.

Share grants support `view` and `download`, are scoped to active users, may have an optional expiration, and can be revoked or reactivated. Preview and download are separate authorized operations. Grants, revocations, successful access, and denied access are audited. Audit records are protected against updates and deletes by SQLAlchemy ORM event listeners.

## 7. Testing

The backend suite uses `unittest` and pytest-compatible fixtures with an isolated in-memory SQLite database:

```bash
python -m unittest
# or
python -m pytest -v
```

The suite covers authentication, role enforcement, administrator review, health checks, models, audit behavior, uploads and SHA-256 integrity, legacy hash baselines, ownership, expiring/revoked sharing, previews, downloads, and authorization failures. Build the frontend with `npm run build` from `frontend/`.

## 8. Setup and Environment Configuration

Prerequisites: Python, Node.js/npm, and (for PostgreSQL) a reachable PostgreSQL instance.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
alembic upgrade head
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Create the first administrator from a trusted interactive terminal with `python -m app.bootstrap_admin`. This one-time command prompts for the account details and password without accepting credentials through command-line arguments; it refuses to run once an administrator exists. Public registration always creates a viewer account.

In another terminal:

```powershell
Set-Location frontend
npm install
npm run dev
```

Open `http://localhost:3000`. The frontend uses `http://127.0.0.1:8000` by default. Set `VITE_API_BASE_URL` to a different backend URL when needed. Configure backend settings in `.env`; notable settings include `DATABASE_URL`, `SECRET_KEY`, `CORS_ORIGINS`, `STORAGE_DIR`, and `MAX_UPLOAD_SIZE_BYTES`. SQLite is the default for local development. For PostgreSQL, use a `postgresql+psycopg://...` URL. Never put backend secrets in frontend environment variables or commit `.env`.

## 9. Deployment

The repository does not include deployment manifests or a production process manager. Before starting with `APP_ENV=production`, configure these environment variables outside source control:

```text
APP_ENV=production
DEBUG=False
SECRET_KEY=<randomly generated key of at least 32 characters>
CORS_ORIGINS=https://vault.example.com
DATABASE_URL=postgresql+psycopg://<database-user>:<database-password>@<database-host>:5432/<database-name>
STORAGE_DIR=<persistent private storage directory>
```

Generate a cryptographically random signing key (for example, generate one with `openssl rand -hex 32`); startup rejects the development fallback, short keys, or an unset production CORS allowlist. Set `CORS_ORIGINS` to a comma-separated list of exact frontend origins; production does not use localhost defaults and rejects an allowlist containing only loopback origins. Keep `DEBUG=False`, serve the API and frontend over HTTPS, and ensure private storage is not exposed as static content. Apply Alembic migrations as part of release, back up the database and storage, and use a production ASGI process manager rather than the development command above.

## 10. Future Improvements

- Add a documented production deployment target and automated release pipeline.
- Add malware scanning and managed/object storage lifecycle controls for uploaded files.
- Add account recovery and user self-service administration.
- Add pagination for large document, share, and audit histories.
- Extend audit-log retention and tamper evidence beyond application-level ORM protections.
