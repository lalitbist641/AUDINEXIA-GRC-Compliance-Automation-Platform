# Audinexia — GRC Compliance Automation Platform

Audinexia is a multi-tenant Flask platform for running a governance, risk and compliance program around
policy documents. It scans an uploaded policy against structured frameworks (**DPDPA 2023, ISO 27001:2022,
GDPR, PCI DSS v4.0, HIPAA, NIST CSF 2.0, CERT-In Directions 2022**), then carries the results into the workflows an audit actually
needs: evidence, a risk register, audit and finding management with approvals, vendor risk, document
monitoring and a tamper-evident audit trail.

> **What the scanner is, and is not.** It checks whether the language a control expects appears in a document
> (whole-word matches, with a same-sentence negation check) and reports **Language found / Partially found /
> Not found**. That is phrase coverage, not a compliance verdict: every result starts unreviewed and needs a
> human reviewer. There is no machine-learning model in the pipeline, and the "remediation draft" fills static
> templates for missing controls. See [SECURITY.md](SECURITY.md) for the full list of limitations.

## What is in it

| Area | What it does |
| --- | --- |
| Scanning | Upload `.txt` / `.pdf` / `.docx`; per-control evidence, language-match coverage, risk-tiered findings, HTML and PDF export, draft remediation text |
| Reviews and evidence | Reviewer confirm/override per control result, evidence file upload and download, remediation status |
| Crosswalk | Shows how one scan maps onto the other frameworks' controls |
| Risk register | Likelihood x impact scoring, owners, linked controls, **risk acceptance with a request and a different manager's approval, time-limited** |
| Audits and findings | Audits, findings with severity and owners, **closure by request and independent approval, closed audits locked, reopen (org_admin + reason) or withdraw** |
| Vendor risk | Vendor register, assessments, contracts, document-to-control links |
| Maturity and monitoring | Recorded maturity claims against scan evidence; watches that re-check a tracked document |
| Audit trail | Per-organization, hash-chained event log of who changed what |
| Administration | Users and roles (org_admin, compliance_manager, auditor, member), password policy and reset, organization settings |
| API | JSON API under `/api`, OpenAPI at `/api/openapi.json` and `/docs`, health and metrics at `/healthz`, `/readyz`, `/version`, `/metrics` |

Roles: `org_admin`, `compliance_manager`, `auditor`, `member`. Every organization-scoped query filters by
`org_id`; another organization's record answers 404.

## Quick start

Requires **Python 3.10+**. SQLite is used out of the box; no other service is needed.

### macOS / Linux

```bash
git clone https://github.com/lalitbist641/AUDINEXIA-GRC-Compliance-Automation-Platform.git
cd AUDINEXIA-GRC-Compliance-Automation-Platform/backend
./setup.sh
source venv/bin/activate
python app.py
```

### Windows (PowerShell)

```powershell
git clone https://github.com/lalitbist641/AUDINEXIA-GRC-Compliance-Automation-Platform.git
cd AUDINEXIA-GRC-Compliance-Automation-Platform\backend
.\setup.ps1
venv\Scripts\activate
python app.py
```

The setup script creates a virtual environment, installs dependencies, writes a `.env` with fresh random
secrets (never committed; see `.env.example`) and runs the database migrations. Then open
**http://127.0.0.1:5000/login** and create an organization.

The app **refuses to start** if `SECRET_KEY` or `JWT_SECRET_KEY` is missing, shorter than 32 characters or a
placeholder. Debug mode is off unless you set `FLASK_DEBUG=1`. Session cookies are `Secure` by default, which
Chrome, Edge and Firefox accept on `localhost`; if your browser refuses them over plain HTTP (Safari), set
`COOKIE_SECURE=0` in `.env`, and never behind real HTTPS.

### Manual setup

```bash
cd backend
python -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env     # then set long random SECRET_KEY and JWT_SECRET_KEY
flask db upgrade
python app.py
```

For a reproducible install use the hash-pinned set: `pip install --require-hashes -r requirements.lock`.

## Configuration

Everything is an environment variable (see `backend/.env.example`). The ones that matter first:

| Variable | Purpose |
| --- | --- |
| `SECRET_KEY`, `JWT_SECRET_KEY` | Required, 32+ characters |
| `DATABASE_URL` | Defaults to SQLite; use `postgresql://...` for PostgreSQL (also `pip install -r requirements-postgres.txt`) |
| `CORS_ORIGINS` | Comma-separated origins allowed to call the API cross-origin. Empty means CORS is off |
| `COOKIE_SECURE` | `true` (default) for HTTPS deployments |
| `MAIL_HOST` and the other `MAIL_*` | SMTP for password-reset email; without it the link is only logged |
| `APP_BASE_URL` | Origin used to build the reset link |
| `HIBP_CHECK_ENABLED` | Breached-password check (fails open) |
| `RATE_LIMIT_*` | Login, register, scan and password-reset limits; use a shared store with several workers |

## Production

`python app.py` is for development. Use a WSGI server, for example
`gunicorn -w 4 -b 0.0.0.0:8000 "app:create_app()"` (gunicorn does not run on Windows), behind HTTPS, with
PostgreSQL and a shared rate-limit store. Several workers on SQLite is not supported.

## Tests

```bash
cd backend
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest tests -q
```

218 tests cover scoring and framework content, tenancy and role checks, authentication and password reset,
the approval and locking workflows, the audit trail, migrations, startup hardening and the frontend
guards (no inline script, CSP shape, every UI action has a handler). Sample policies for manual scanning are
under `backend/policies/`.

## Project structure

```
backend/
  app.py            Application factory, page routes, error handlers
  config.py         Environment-driven configuration and startup checks
  models.py         Organization, User, Assessment, ControlResult, Risk, Audit, Finding, Vendor, ...
  auth.py           Register, login, refresh, logout, change/reset password, /me
  rbac.py           roles_required and org-scoping helpers
  security.py       Headers/CSP, rate limiting, password policy, forced-password-change gate
  scanning.py       Framework definitions, phrase matching, scoring
  reports.py        HTML / PDF / remediation report generation
  crosswalk.py      Cross-framework mapping
  routes/           scan, assessment, review, risk, audit, vendor, maturity, monitoring, admin
  core/             audit trail, mailer, monitoring, vendor risk, maturity, OpenAPI
  templates/        login.html, dashboard.html, error.html
  static/js/        auth.js (session), dashboard.js, login.js
  migrations/       Alembic history
  tests/            pytest suite
frontend/           Unused React scaffold; the served UI is backend/templates + static/js
```

## Documentation

- [SECURITY.md](SECURITY.md): reporting, protections, and known limitations
- [CHANGELOG.md](CHANGELOG.md): what changed
- [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

Licensed under the Apache License 2.0; see [LICENSE](LICENSE).
