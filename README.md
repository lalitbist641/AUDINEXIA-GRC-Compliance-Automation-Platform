# Audinexia — GRC Compliance Automation Platform

Audinexia analyzes an organization's policy documents (privacy policy, security policy, etc.)
against structured compliance frameworks — **DPDPA 2023, ISO 27001:2022, GDPR, PCI DSS v4.0,
HIPAA, and NIST CSF 2.0** (55 controls total) — and produces a weighted compliance score,
per-control evidence, risk-tiered findings, and exportable HTML/PDF reports, with an
AI-assisted remediation draft for missing controls.

The backend is a multi-tenant Flask API (JWT auth, role-based access control, SQLite/Postgres
via SQLAlchemy) with a server-served dashboard UI. See
[`Audinexia_Project_Report.pdf`](Audinexia_Project_Report.pdf) for the full technical writeup.

## Quick start

Requires **Python 3.10+**. No external services (no Postgres/Redis/etc. required) — SQLite is
used out of the box.

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

Either script creates a virtual environment, installs dependencies, generates a `.env` with
fresh random secret keys (never committed — see `.env.example` for the format), and runs the
initial database migration. Then open **http://127.0.0.1:5000/login** and create an
organization to get started.

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
# then edit .env and set your own SECRET_KEY / JWT_SECRET_KEY (any random string)

flask db upgrade            # creates instance/audinexia.db
python app.py
```

## Running the tests

There is no automated test suite yet for this phase — see the "Current Limitations" section of
the project report. Manual validation samples are provided under `backend/policies/` (compliant,
partially compliant, and non-compliant sample policies per framework).

## Project structure

```
backend/
  app.py            Flask application factory + top-level routes (/, /login, /dashboard)
  config.py         Config loaded from .env (SECRET_KEY, JWT_SECRET_KEY, DATABASE_URL, ...)
  extensions.py     SQLAlchemy / Flask-Migrate / Flask-JWT-Extended singletons
  models.py         Organization, User, Assessment, ControlResult
  auth.py           /api/auth/* — register, login, refresh, logout
  rbac.py           roles_required decorator + org-scoping helpers
  scanning.py       Framework/control definitions, phrase matching, scoring engine
  reports.py        HTML/PDF/remediation report generation
  routes/           /api/scan, /api/assessments, /api/admin/users
  templates/        login.html, dashboard.html (server-served vanilla-JS SPA)
  static/js/        auth.js (Bearer-token session handling)
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

Then run `flask db upgrade` again against the new database.
