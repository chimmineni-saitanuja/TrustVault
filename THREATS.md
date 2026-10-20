# TrustVault — Threat Model and Security Analysis

This document provides a realistic, honest security analysis of TrustVault, detailing threat vectors, planned mitigations, verification test cases, and accepted risks.

---

## 1. Threat Scenarios & Mitigations

### Threat 1: Insecure Direct Object References (IDOR)
- **Scenario**: An attacker discovers or increments a document identifier (e.g. `/documents/123`) to view or download a document belonging to another user.
- **Impact**: High. Confidential document disclosure.
- **Mitigation**:
  1. Primary keys for documents, users, and permissions use 128-bit random UUIDs (`uuid.uuid4()`), making sequential guessing impossible.
  2. Server-side permission verification on every request. Document queries will explicitly join permissions or verify ownership before returning data.
- **Verification Tests**:
  - `tests/test_models.py` (UUID generation verified in Milestone 1).
  - Cross-user authorization tests (Scheduled for Milestone 2 & 3).
- **Status**: **Foundation Implemented (UUIDs)** / Full API checks pending Milestone 2.

---

### Threat 2: Audit Log Tampering (Log Mutation or Deletion)
- **Scenario**: A malicious actor or compromised internal user modifies or deletes audit logs to conceal unauthorized access, data exfiltration, or illegal permission changes.
- **Impact**: Critical. Loss of forensics and accountability.
- **Mitigation**:
  1. **Application-Level Immutability**: SQLAlchemy ORM event listeners (`before_update`, `before_delete`) intercept and reject any modification or deletion of `AuditEvent` instances with a `ReadOnlyAuditLogError`.
  2. **Database-Level Constraint**: PostgreSQL append-only policy / triggers.
- **Verification Tests**:
  - `tests/test_models.py::test_audit_event_immutability_prevent_update` (Verified).
  - `tests/test_models.py::test_audit_event_immutability_prevent_delete` (Verified).
- **Status**: **Milestone 1 Implemented & Verified**.

---

### Threat 3: Audit Loss via Resource Deletion
- **Scenario**: An attacker deletes a sensitive document or user account to automatically trigger a cascade delete that purges related audit records.
- **Impact**: High. Forensic evidence erased.
- **Mitigation**:
  1. The `AuditEvent` table does not enforce cascading deletion on documents. The `resource_id` field is stored as a standalone string identifier rather than a cascading foreign key.
  2. `actor_id` uses `ON DELETE SET NULL`, while `actor_email` is preserved as a snapshot at the time of the event.
- **Verification Tests**:
  - `tests/test_models.py::test_audit_event_records_denied_attempt_with_context` (Verified).
- **Status**: **Milestone 1 Implemented & Verified**.

---

### Threat 4: Audit Evasion via Denied Requests
- **Scenario**: An attacker attempts multiple unauthorized operations. If only successful operations are logged, security teams cannot detect brute-force or privilege escalation probes.
- **Impact**: High. Undetected intrusion attempts.
- **Mitigation**:
  1. `AuditEvent` schema explicitly supports `AuditOutcome.DENIED` and `AuditOutcome.ERROR`.
  2. Detailed denial metadata (`reason`, `ip_address`, `user_agent`, `context_metadata`) is recorded when unauthorized operations are blocked.
- **Verification Tests**:
  - `tests/test_models.py::test_audit_event_records_denied_attempt_with_context` (Verified).
- **Status**: **Milestone 1 Schema Implemented** / Integration in authorization interceptor pending Milestone 2 & 3.

---

### Threat 5: Stale Access Post-Revocation
- **Scenario**: An owner revokes a user's permission, but the user continues accessing the document using pre-signed reusable URLs or cached session tokens.
- **Impact**: Critical. Non-immediate revocation violates compliance.
- **Mitigation**:
  1. Permissions check will query the live database on every download request (`is_revoked == False`).
  2. No long-lived pre-signed URLs; file downloads are served through authenticated streaming backend endpoints that enforce instantaneous revocation checks.
- **Verification Tests**:
  - Revocation denial tests (Scheduled for Milestone 3).
- **Status**: **Pending Milestone 3**.

---

### Threat 6: Direct API Bypass (Bypassing Frontend UI)
- **Scenario**: An attacker ignores the web frontend and issues raw HTTP requests directly to API endpoints (e.g., using `curl` or Postman) attempting to execute privileged actions.
- **Impact**: High.
- **Mitigation**:
  1. The backend never relies on client-side state, hidden buttons, or frontend flags.
  2. Every endpoint independently enforces JWT validation, role checks, and document ownership/permission verification.
- **Verification Tests**:
  - Backend API direct HTTP tests via HTTPX/TestClient.
- **Status**: **Pending Milestone 2**.

---

## 2. Accepted Risks & Honest Limitations

1. **Superuser Database Access**:
   - An administrator with root/superuser access directly to the PostgreSQL instance can bypass ORM hooks and modify database tables directly. Mitigating this would require write-once-read-many (WORM) hardware or external cryptographic ledger streaming, which is documented here as an accepted risk for this deployment tier.
2. **Denial of Service via Heavy Audit Logging**:
   - High volumes of failed requests will write audit records to the database. Rate limiting will be evaluated in Milestone 3 to prevent disk exhaustion.
