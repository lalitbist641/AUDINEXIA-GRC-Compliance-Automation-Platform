# Changelog

All notable changes to this project are documented here. Dates are when the work was completed,
not necessarily when it was tagged as a release (this project does not yet follow formal semantic
versioning — that's part of the industry-readiness roadmap).

## Unreleased — Phase 0: Critical fixes

Following an external technical/security review, closing the blockers the review identified as
prerequisites for any further work: licensing, hard-fail on weak secrets, per-request auth
revocation, stored-XSS fixes with CSP and cookie-based tokens, honest (non-fabricated) scanner
statuses with negation detection, an append-only audit log with soft deletes, segregation-of-duties
enforcement on risk/finding closure, closed-audit immutability, dependency/PDF-DOCX fixes, user
lifecycle management, and documentation accuracy. See `SECURITY.md` for the specific gaps still
open after this phase (CSP `unsafe-inline` pending an onclick-handler migration, password-reset
email delivery not yet wired to a provider).

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
