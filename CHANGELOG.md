# Changelog

Entries describe what is in the code and tested, not what is planned. Remaining gaps are in
[SECURITY.md](SECURITY.md).

## Unreleased

### Added
- **CERT-In Directions (28 April 2022)** as a seventh framework (`certin`, 8 controls): 6-hour incident reporting,
  Annexure I incident types, point of contact, NTP clock synchronisation, 180-day log retention within India,
  cooperation with CERT-In requests, and the two entity-specific record-keeping duties (subscriber records for
  data centre/cloud/VPN providers; KYC and transaction records for virtual asset providers). It is wired through
  the scanner, reports, draft revised policy, dashboard and API docs, with sample policies under `backend/policies/`.
  The control text is a plain-language summary written for this scanner, not the legal text; it has had no legal
  review. Controls 7 and 8 apply only to the entity types named above, so other organisations correctly see
  "Not found" there.
- Not added: CERT-In is not in the crosswalk. Its phrases do not overlap the existing clusters' phrases, and the
  crosswalk only links controls that share required phrases.

### Changed
- A framework's content hash now covers only the synonym entries its own phrases use, so adding a framework or an
  unrelated synonym no longer flags every scan of every other framework as scored against a changed definition.
  Moving to this scheme changes every framework's hash once: scans stored before this change will show as
  "framework definition drift" when re-scanned.

## Phase 0 hardening (from the industry-readiness review)

Scope: the review's "Phase 0: critical fixes" (items 2.1 to 2.12). The 9 to 12 month roadmap that follows it
(new scanning engine, PostgreSQL row-level security, SSO/MFA, integrations) is not part of this change.

### Security
- The app refuses to start with a missing, short or placeholder `SECRET_KEY` / `JWT_SECRET_KEY`.
- Debug mode is opt-in (`FLASK_DEBUG`); the app no longer starts the Werkzeug debugger by default.
- CORS is off unless `CORS_ORIGINS` lists origins; the wildcard is gone.
- Sessions moved from tokens in `sessionStorage` to httpOnly, `SameSite=Strict` cookies with a CSRF header.
  The browser keeps only a non-secret profile; `/api/auth/me` confirms the session on every dashboard load.
- Strict script CSP (`script-src 'self'`): inline scripts moved to `static/js/dashboard.js` and `login.js`;
  73 inline `onclick` handlers replaced by `data-action` attributes and one delegated listener whose arguments
  are parsed as JSON, never evaluated.
- Every interpolated value in the dashboard's HTML is escaped; HTML and PDF report builders escape too.
  Verified by injecting `<img onerror>` / `</textarea><script>` payloads into risks, audits, findings and
  vendors and confirming they render as text, with a positive control that the check can see an injected image.
- Self-service password reset: single-use hashed token, 30-minute expiry (`PASSWORD_RESET_MINUTES`),
  enumeration-safe response, rate limited, all existing tokens invalidated on use. Mail is sent over SMTP when
  `MAIL_*` is configured and logged otherwise.
- Breached-password check (HIBP range API, k-anonymity, fails open) applied to register, reset, change and
  admin-set passwords.

### Governance controls
- **Segregation of duties:** a risk owner or finding owner cannot accept their own risk or close their own
  finding. They submit a request with a written reason; a different manager approves or rejects it. The
  approver is checked against the owner id and the requester id, not just the role.
- **Audit locking:** closing an audit locks it and its findings. Reopening needs an `org_admin` and a reason.
  An audit that has progressed past `planned` is withdrawn (with a reason) instead of deleted.
- **Soft deletes** for risks, findings, audits and evidence, with `deleted_at` / `deleted_by_id`.
- **Tamper-evident audit trail:** each event is chained to the previous one by SHA-256. See SECURITY.md for what
  that does and does not prove.
- Dashboard screens for all of the above: request and approve/reject risk acceptance and finding closure,
  reopen or withdraw an audit, locked-audit state.

### Scanner honesty
- Status labels are **Language found / Partially found / Not found**; results start as unreviewed and the UI marks
  them provisional. "Compliance score" became "language-match coverage".
- Whole-word matching (short terms like `rto` no longer match inside `report`), a same-sentence negation check,
  and overly generic synonyms removed. `MATCHER_VERSION` is part of the framework content hash, so reports state
  which matcher produced them. A migration rewrites previously stored statuses to the new vocabulary.

### Fixes
- Creating or deleting a finding raised `AttributeError` (the audit-trail call read a `title` column that
  findings do not have).
- Any unknown non-API URL returned 500 because `templates/error.html` did not exist.
- `setup.ps1` wrote `.env` with a byte-order mark, which hid `SECRET_KEY` from the loader.

### Dependencies and repo
- Flask 2.3 to 3.1, Werkzeug 2.3 to 3.1, flask-cors 4 to 6, gunicorn 22 to 23, PyYAML 6.0.3, pdfplumber 0.11.10.
  `backend/requirements.lock` is a hash-pinned install set; `pip-audit` reported no known vulnerabilities for it.
  Dependabot is configured for `backend/`.
- Apache-2.0 `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, this changelog.
- 218 automated tests (was 123 on the base branch), including cross-tenant, workflow, hardening and frontend
  guard tests.

### Changed behavior to be aware of
- API clients that relied on a wildcard CORS policy must now be listed in `CORS_ORIGINS`.
- Nobody, managers included, can set a finding to `resolved`, `accepted_risk` or `closed`, or a risk to
  `accepted`, with a plain status edit; use `request-closure` / `approve-closure` and
  `request-risk-acceptance` / `approve-risk-acceptance`. A risk owner (member role) also cannot set `closed`.
- Crosswalk `status_breakdown` keys are now `language_found`, `partially_found`, `not_found`.
