# Audinexia — GRC Compliance Automation Platform

Audinexia is a multi-tenant GRC (Governance, Risk, Compliance) platform. It analyzes an
organization's policy documents against structured compliance frameworks — **DPDPA 2023,
ISO 27001:2022, GDPR, PCI DSS v4.0, HIPAA, and NIST CSF 2.0** (55 controls total) — and
builds out the workflow around that scan: evidence collection, remediation tracking, a
risk register, audit management, and a cross-framework control crosswalk.

The scanner itself is phrase-matching, not a language model: `/api/revise-policy`
(remediation drafts) and the compliance-status labels it produces are template text and
deterministic scoring, not an AI judgment call. See `SECURITY.md` and `CHANGELOG.md` for
what's built, what's a known interim state, and what's explicitly out of scope for now.

The backend is a Flask API (JWT auth, role-based access control, SQLAlchemy/SQLite —
swappable to Postgres via one environment variable) with a server-rendered dashboard UI.

## What's built

- **Compliance scanning** — upload a policy (.txt/.pdf/.docx), get a per-control score
  against one of the six frameworks, with the matched/missing phrases shown as evidence.
- **Evidence & remediation workflow** — attach supporting files to a control result,
  assign an owner and due date, track review/remediation status.
- **Risk register** — likelihood/impact are always explicit human input, never inferred
  from scan data; risk score/level are the only auto-computed parts (deterministic
  arithmetic on numbers a person entered). Accepting a risk requires a written
  justification, an expiry date, and sign-off from a manager who isn't the risk's owner.
- **Audit management** — plan → in-progress → completed → closed engagements with
  findings. A closed audit is locked against further changes; reopening needs an
  org_admin and a stated reason. Closing a finding follows the same manager-approval
  pattern as risk acceptance.
- **Framework crosswalk** — maps a control's evidence across frameworks that genuinely
  share the same required language (encryption, access control, incident response, etc.),
  shown as categorical status only — never a synthesized aggregate score.
- **Multi-tenant RBAC** — every org-scoped query filters by `org_id` directly (never
  fetch-then-check); five roles (`org_admin`, `compliance_manager`, `auditor`, `member`,
  `read_only`); an append-only, hash-chained audit log records who changed or deleted what.

## Quick start

Requires **Python 3.10+**. No external services (no Postgres/Redis/etc. required) — SQLite
is used out of the box.

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

Either script creates a virtual environment, installs dependencies, generates a `.env`
with fresh random secret keys (never committed — see `.env.example` for the format), and
runs the initial database migration. Then open **http://127.0.0.1:5000/login** and create
an organization to get started.

### Manual setup (any OS, if you'd rather not use the scripts)

```bash
cd backend
python -m venv venv
# macOS/Linux:
source venv/bin/activate
# Windows:
venv\Scripts\activate

pip install -r requirements.txt
cp .env.example .env        # Windows: copy .env.example .env
# then edit .env: SECRET_KEY and JWT_SECRET_KEY must each be 32+ random
# characters and not contain "change-me" -- the app refuses to boot
# otherwise. Generate one with:
#   python -c "import secrets; print(secrets.token_hex(32))"

flask db upgrade            # creates instance/audinexia.db
python app.py
```

### Running in production

`app.py`'s built-in dev server (`python app.py`) runs with Werkzeug's debugger off by
default (`FLASK_DEBUG=0`) — leave it that way outside local development; the debugger's
console can execute arbitrary Python for anyone who can reach it. For an actual
deployment, run the app factory behind a real WSGI server instead:

```bash
gunicorn -w 4 -b 0.0.0.0:8000 "app:create_app()"
```

(`gunicorn` doesn't run on Windows — use it from a Linux host/container.) There's no
reverse proxy, TLS termination, or process manager configuration here; that's
infrastructure this project doesn't currently ship or document.

## Running the tests

There is no automated test suite yet — see `SECURITY.md` for this and other known gaps.
Manual validation samples are provided under `backend/policies/` (compliant, partially
compliant, and non-compliant sample policies per framework).

## Project structure

```
backend/
  app.py            Flask application factory + top-level routes (/, /login, /dashboard)
  config.py         Config loaded from .env; refuses to boot on a missing/weak/default secret
  extensions.py     SQLAlchemy / Flask-Migrate / Flask-JWT-Extended / Flask-Limiter singletons
  models.py         Organization, User, Assessment, ControlResult, EvidenceFile, Risk,
                     Audit, Finding, AuditEvent, and their join tables
  auth.py           /api/auth/* -- register, login, refresh, logout, change-password,
                     request/reset password
  rbac.py           roles_required decorator + org-scoping helpers (DB-backed, re-checked
                     on every request -- not just read from the JWT's claims)
  security.py       Password strength rule, breach check, reset-token hashing
  audit_log.py      Append-only, hash-chained audit trail (record_audit_event/verify_chain)
  scanning.py       Framework/control definitions, phrase matching, scoring engine
  crosswalk.py       Cross-framework control mapping
  reports.py        HTML/PDF/remediation report generation
  routes/           /api/scan, /api/assessments, /api/risks, /api/audits,
                     /api/admin/users, evidence & review endpoints
  templates/        login.html, dashboard.html (server-served vanilla-JS SPA)
  static/js/        auth.js (session handling)
  migrations/       Alembic migration history (tracked in git so a fresh clone can run
                     `flask db upgrade` without regenerating migrations)
frontend/           Empty React scaffold, not currently used (the served UI is
                     backend/templates/dashboard.html)
```

## Switching to PostgreSQL

The app uses SQLAlchemy, so switching off SQLite is just an environment variable change —
no code changes needed:

```
DATABASE_URL=postgresql://user:password@host:5432/audinexia
```

Then run `flask db upgrade` again against the new database. Row-level tenant isolation
enforced at the database level (rather than relying on every query remembering to filter
by `org_id`) is a planned follow-up, not yet implemented.
