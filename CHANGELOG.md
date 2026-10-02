# Changelog

All notable changes to this project are documented here. Dates are when the work was completed,
not necessarily when it was tagged as a release (this project does not yet follow formal semantic
versioning — that's part of the industry-readiness roadmap).

## Unreleased — Phase 0: Critical fixes (in progress)

Following an external technical/security review, closing the blockers the review identified as
prerequisites for any further work. Landed so far:

- Licensing and repo hygiene (Apache-2.0, SECURITY.md, removed a leaked local path and a personal
  photo from git history).
- Hard-fail at boot on a missing/weak/default `SECRET_KEY` or `JWT_SECRET_KEY`.
- Per-request auth revocation: every request re-checks the caller against the database (active
  status, current role, a `token_version` bumped by logout/password-change/admin action) instead of
  trusting claims baked into the JWT at login time. Full user lifecycle: admin role/status changes,
  change-password, password reset (token generated and validated correctly; the reset link is
  logged server-side, not emailed — no SMTP provider configured in this environment), login rate
  limiting and account lockout, NIST 800-63B password length rule with a best-effort breach check.
- Append-only, hash-chained audit log (who changed or deleted what, and when) plus soft deletes on
  Risk/Finding/Audit/EvidenceFile — nothing is hard-deleted through the API anymore for these.
- Segregation of duties: an owner can no longer set their own risk to "accepted" or their own
  finding to a closed status directly — they submit a request, and a *different* manager must
  approve it.
- Closed-audit immutability: a closed audit (and its findings) is locked against further changes;
  reopening requires an org_admin and a stated reason. A `withdrawn` status replaces deletion once
  an audit has progressed past `planned`.
- Honest scanner output: statuses renamed from "Compliant/Partially Compliant/Non-Compliant" to
  "Language found/Partially found/Not found" (the scanner counts required phrases; it doesn't judge
  whether a control is effective), the overall score is labeled "language-match coverage" with a
  disclaimer, and unreviewed results are visibly marked provisional. Phrase matching is now
  whole-word with negation detection ("we do not encrypt data" no longer counts as evidence), and
  overly generic synonyms were removed. The negation heuristic is a short lookback window within
  the same sentence — a known-imperfect interim measure, not a real language understanding step.
  Also fixed: four duplicate `PHRASE_SYNONYMS` keys that were silently discarding synonym lists,
  a hardcoded "100% Compliant" claim on the revised-policy PDF (now an explicit unverified-draft
  banner), and a missing import that made the revised-policy PDF endpoint fail with a 500.
- Dependency/PDF-DOCX extraction fixes (see the dated entry below), debug server and wildcard CORS
  disabled by default, documentation accuracy pass (this file included).

Still open, tracked honestly rather than silently deferred — see `SECURITY.md` for the current
detail on each: stored-XSS fixes in the dashboard UI, a Content-Security-Policy header, and moving
JWTs from `sessionStorage`/bearer-token to httpOnly cookies; the Flask/Werkzeug/flask-cors
dependency upgrade.

## Phase 5 — Audit Management

- `Audit` and `Finding` models with a planned → in_progress → completed → closed lifecycle.
- Closing an audit is rejected while any finding remains open.
- Owner-carve-out RBAC on findings (a `member`-role owner may update status/management response on
  their own finding; everything else needs a manager role).

## Phase 4 — Risk Register

- `Risk` model: human-entered likelihood/impact (never auto-computed), server-computed risk score
  and level via a 4-band 5×5 matrix.
- `RiskControlLink` join table linking risks to specific scanned control findings.

## Phase 3 — Framework Crosswalk Engine

- Cross-framework control mapping verified directly against each framework's actual required-phrase
  lists (not guessed from similar names) — 7 clusters covering encryption, access control, incident
  response, data subject rights, monitoring, vulnerability management, and DPO designation.
- Projects only categorical status across frameworks, never a numeric score or synthesized
  aggregate coverage figure.

## Phase 2 — Evidence & Remediation Workflow

- `EvidenceFile` model, evidence upload/download tied to a specific control result.
- Reviewer workflow (`reviewer_status`, assignment, due dates) and `remediation_status` tracking on
  scanned control results.
- Report regeneration from a stored `assessment_id` instead of trusting client-submitted JSON.

## Phase 1 — Multi-Tenant GRC Foundation

- SQLAlchemy models, Flask-Migrate, JWT authentication, RBAC (`org_admin` / `compliance_manager` /
  `auditor` / `member` / `read_only`), organization-scoped data isolation.
- Split the original single-file scanner into a proper backend package.
- One-command setup scripts (`setup.sh` / `setup.ps1`) for a fresh clone.

## Pre-Phase-1

Original single-file Flask prototype: keyword/phrase-matching compliance scanner across 6
frameworks (DPDPA, ISO 27001, GDPR, PCI DSS, HIPAA, NIST CSF), no database, no authentication.
