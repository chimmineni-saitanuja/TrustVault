# TrustVault Project Brief: Requirements and Architecture

This brief describes TrustVault's product scope and current implementation for contributors and coding assistants. It is an architectural summary of this repository, not an organizer-issued hackathon specification. Development-stage labels are intentionally omitted.

## Product Goal

Build a document workspace where users can store files privately, grant narrowly scoped access to other registered users, and revoke that access. Enforce authorization in the FastAPI backend; frontend visibility is not a security boundary.

## Implemented Requirements

### User experience

- Users can register, sign in, inspect their own profile, and sign out.
- The React application separates owned documents from documents shared with the current user.
- Owners can upload, search, preview, and download their documents, and manage document shares.
- Recipients can list active shares and preview a document with an active `view` or `download` grant. A Download action is available only for a `download` grant; the backend enforces this independently. Owners can optionally set a timezone-aware expiration when granting access; expired and revoked grants do not authorize access.
- Users can review their own recent, safely-filtered events in the Activity Log.

### API and authorization

- `POST /auth/register` creates a viewer account and returns a public profile; `POST /auth/login` returns a bearer JWT; `GET /auth/me` returns the authenticated user's profile.
- The backend validates the signed token and reloads the user from the database, rejecting inactive accounts.
- `GET /documents/` and `GET /documents/{document_id}` expose only owned documents.
- Owners and admins can grant, list, and revoke shares. Grants are limited to `view` and `download` for existing active users.
- `GET /documents/shared-with-me` returns documents having an active permission for the authenticated user.
- `GET /activity/` returns recent events for the authenticated actor, with document and related-user labels limited to details the user can currently access.
- Preview requires ownership or an active `view`/`download` permission. Download requires ownership or an active `download` permission. Admin status alone does not grant file access.
- `GET /users/` is admin-only.

### Storage and audit

- Supported uploads are PDF, PNG, JPEG, and text, with file-size limits and file-type checks.
- The API stores files under generated names in private `STORAGE_DIR`; client-facing responses do not return internal storage paths.
- The backend resolves file paths within the configured storage root before serving them.
- Uploads are SHA-256 hashed in chunks; authorized preview and download requests verify the digest before serving. Legacy records have a nullable hash and establish a baseline on first authorized access. That trust-on-first-use baseline cannot establish historical integrity; compare legacy files to a trusted source before first access when that assurance is required.
- Share-grant expiration is optional, timezone-aware, and normalized to UTC. A missing expiration means the grant remains active until revoked.
- Authentication outcomes and document/share operations are audited. Audit events are append-only at the SQLAlchemy ORM layer.

## Architecture

- **Frontend:** React 18, TypeScript, Vite, and `lucide-react`; API calls are centralized in `frontend/src/api.ts`. The frontend stores its bearer token in `sessionStorage`.
- **Backend:** FastAPI application and routers in `app/routers/`, Pydantic request/response schemas in `app/schemas/`, authentication dependencies in `app/dependencies.py`, and cryptographic helpers in `app/security.py`.
- **Persistence:** SQLAlchemy 2.x models in `app/models.py`; Alembic migrations in `migrations/`. SQLite is the local default; PostgreSQL is supported using `psycopg` v3.
- **Tests:** `tests/` contains `unittest` cases and pytest-compatible fixtures using isolated in-memory SQLite.

## Important Security Boundaries

- Do not trust the frontend to decide whether a user may view or download a document.
- Keep passwords, JWTs, signing keys, and internal storage paths out of logs and public responses.
- Do not serve files directly from a public/static directory. Preserve path containment checks and active-grant checks in all file-serving routes.
- Keep share changes and their audit records consistent; preserve generic unauthorized-resource responses where already used.
- Treat current ORM audit immutability as application-level protection, not a guarantee against privileged database operators or direct database writes.

## Configuration and Local Development

Backend configuration is read from environment variables or `.env` through Pydantic Settings. Defaults include local SQLite, `storage/documents`, and a 10 MiB upload limit. Copy `.env.example` to `.env`, set a strong `SECRET_KEY` for non-local use, apply migrations with `alembic upgrade head`, and start the API with Uvicorn. Start the Vite frontend from `frontend/`; it defaults to `http://127.0.0.1:8000` and accepts `VITE_API_BASE_URL`.

Run backend tests with `python -m unittest` or `python -m pytest -v`; build the frontend with `npm run build` from `frontend/`.

## Planned, Not Yet Implemented

- Production deployment manifests, release automation, and hosting-specific configuration.
- Malware scanning and managed object-storage lifecycle management.
- Account recovery and self-service user administration.
- Pagination for growing document, share, and audit collections.
- Audit retention and tamper-evidence controls beyond ORM event listeners.

When extending the project, preserve current ownership and grant semantics, add tests for both permitted and denied access, and update this brief and `README.md` when implemented behavior changes.
