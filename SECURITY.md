# Security Policy

Audinexia holds sensitive material: an organization's policy documents, its risk register, unresolved audit
findings. This file says how to report a vulnerability, what the platform does to protect that data, and, just
as important, what it does not yet do.

## Status: pre-GA

Audinexia is a portfolio / research project working through an industry-readiness plan. It is **not yet suitable
for production use with real sensitive data.** The limits below are listed so nobody has to discover them.

### Known limitations

**Not yet done**
- No third-party penetration test has been performed.
- No legal review of the framework content: the control text in the scanner has not been checked against the licensing terms of the standards bodies (ISO, PCI SSC, etc.).
- PostgreSQL row-level security, SSO/SAML/OIDC, MFA and SCIM are not implemented. SQLite is the default database.
- The scanner is phrase matching, not an assurance engine (see "Scanner honesty" below).

**Browser security**
- The Content-Security-Policy is `script-src 'self'`: no inline scripts, no inline event handlers, no `eval`.
  `style-src` still allows `'unsafe-inline'` because the templates use `style=""` attributes. That cannot execute
  code, but it is a gap against a fully strict policy.
- XSS protection is a convention, not a proof: every interpolated value in the dashboard's HTML strings goes
  through `esc()`, and reports escape server-side. `tests/test_frontend_guards.py` pins the mechanical parts (no
  inline script or handlers, every `data-action` has a handler, CSP shape). It does **not** prove that every
  future `${...}` is escaped; review new template code for that.
- Sessions use httpOnly, `SameSite=Strict` cookies with a CSRF double-submit header. API clients that log in
  without the `X-Session-Mode: cookie` header still receive bearer tokens in the response body; those tokens are
  not httpOnly and are the client's responsibility.

**Accounts**
- Password-reset email is sent only if `MAIL_HOST` (and related `MAIL_*` settings) are configured. Otherwise the
  link is written to the server log and the API response says nothing about whether an email exists. Do not rely on
  the flow for a real account until SMTP is configured and tested in your environment.
- The breached-password check (HaveIBeenPwned k-anonymity range API: only a 5-character SHA-1 prefix leaves the
  server) fails open: if the service is unreachable, the password is accepted on the other rules alone.
- `POST /api/auth/register` answers `409 Email already registered`, so it can be used to test whether an email
  has an account. This is a deliberate signup-UX choice. Password reset and login do not leak this.
- A refresh token is revoked on logout when the client sends it or the cookie carries it. A stolen refresh token
  that is never revoked stays usable for its lifetime (7 days by default) unless the account's password is changed,
  which invalidates all of the account's tokens.
- The default rate limiter is in-process memory (per worker). Set `RATE_LIMIT_STORE` to a shared store for
  multi-worker deployments.

**Audit trail**
- Each organization's trail is a SHA-256 hash chain, so editing or deleting an event in the middle is detectable
  (`core.audit_trail.verify_chain`). It is not tamper-proof: someone with write access to the database who rewrites
  the tail of the chain and recomputes the hashes is not detected, because the chain is not anchored anywhere
  external. Rows written before the chain existed are skipped by verification.
- The trail grows with usage; there is no retention or archival job yet.

**Workflow controls**
- Risk acceptance has an expiry date, but nothing flips the status when it passes; the UI shows it as expired and
  asks for re-review.
- Risks, findings, audits and evidence are soft-deleted (`deleted_at`). Vendors, vendor contracts, vendor-control
  links and monitoring watches are still hard-deleted (each deletion is recorded in the audit trail).
- Segregation of duties is enforced by user id: the owner of a risk or finding, and whoever submitted the request,
  cannot approve it. One person holding two accounts defeats that, as with any such control.

**Scanner honesty**
- Results are labelled **Language found / Partially found / Not found**, never "Compliant". They measure whether
  required phrasing appears in a document, and every result starts as `unreviewed` until a human confirms or
  overrides it. The overall number is "language-match coverage", not a compliance score.
- Matching is whole-word, and a phrase preceded in the same sentence by a negation ("we do not encrypt...") is not
  counted as found. This is an interim heuristic: a negation that comes *after* the phrase ("encryption is not
  used") is not caught.
- The API's `compliant_count` / `non_compliant_count` field names are legacy; they now mean "language found" and
  "not found".

## Reporting a vulnerability

Please report security issues privately, not in a public GitHub issue.

- **Email:** lalitbist.edu@gmail.com, subject `SECURITY: <short description>`
- **Include:** the affected commit, steps to reproduce, and the impact you expect (for example "a member can read
  another organization's findings").

### Response targets

This is a solo-maintained project, so these are best-effort targets, not an SLA.

- Acknowledgement: within 3 business days.
- Initial assessment: within 7 business days.
- Fix or documented mitigation for a confirmed critical or high-severity issue: within 14 days of confirmation.

### Scope

In scope: the Flask backend and the server-rendered dashboard in this repository.

Out of scope: issues that need an already-compromised admin account, physical access to the server, or
denial-of-service reports with no resource-exhaustion mechanism.

### Disclosure

Please allow a reasonable window to fix a confirmed issue before public disclosure. There is no bug bounty.

## What the platform does today

- **Startup refuses weak configuration:** the app will not boot with a missing, short (< 32 characters) or
  placeholder `SECRET_KEY` / `JWT_SECRET_KEY`. Debug mode is off unless `FLASK_DEBUG` is set. CORS is off unless
  `CORS_ORIGINS` names origins (no wildcard).
- **Tenant isolation:** every organization-scoped query filters by `org_id` inside the query; a record in another
  organization returns 404, not 403. Covered by the cross-tenant tests.
- **Server-side account state:** role, active flag and token version are re-read from the database on every
  request, so deactivating a user or changing their role takes effect immediately. Tokens can be revoked.
- **Password handling:** length and common-password rules, breached-password check, login lockout and rate limits,
  single-use hashed reset tokens with an enumeration-safe response, forced change for admin-set passwords.
- **Segregation of duties and locking:** risk acceptance and finding closure require a request and a *different*
  manager's approval; closed audits and their findings are locked until an `org_admin` reopens them with a reason.
- **Headers:** CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, HSTS when served over HTTPS,
  `Cache-Control: no-store` on API responses.
- **Dependencies:** direct dependencies are pinned in `backend/requirements.txt`; `backend/requirements.lock` pins
  every package with hashes. The lockfile was audited with `pip-audit` with no known vulnerabilities at the time it
  was compiled; Dependabot proposes updates.
