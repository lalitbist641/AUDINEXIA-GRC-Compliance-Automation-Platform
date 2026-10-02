"""Shared pytest fixtures.

Design notes, because a test suite for this app has two traps:

1. The app reads folders from `Config` class attributes that other modules
   captured with `from config import Config`. Patching `os.environ` after import
   does nothing; patching the attribute does, because every module holds a
   reference to the same class object. So the tmp upload/report dirs are set by
   monkeypatching `Config`, which keeps test runs from writing into the real
   `backend/uploads/` the demo data depends on.

2. The database is a per-test temp *file*, not `:memory:`. Flask-SQLAlchemy plus
   SQLite in-memory gives every connection its own empty schema unless the
   engine is built with StaticPool, and `db.create_all()` inside a request would
   then be invisible to the next one. A temp file is a few milliseconds slower
   and cannot produce that class of flake.

Rate limiting is off by default: the limiter is a process-wide sliding window, so
one shared in-memory bucket across ~80 tests would fail unrelated tests for the
wrong reason. `test_rate_limiting` turns it back on with its own app.
"""

import os
import pathlib
import sys

import pytest

# app.py builds a module-level `app = create_app()` on import, and create_app now
# refuses to start without strong signing secrets. A CI runner has no .env, so
# supply throwaway ones before anything imports the app (individual tests still
# pass their own via create_app overrides).
os.environ.setdefault('SECRET_KEY', 'a1' * 24)
os.environ.setdefault('JWT_SECRET_KEY', 'b2' * 24)

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from config import Config          # noqa: E402
from models import db               # noqa: E402

POLICY_DIR = os.path.join(BACKEND_DIR, 'policies')

# The five roles the product actually ships. Named here rather than
# spelled out per fixture so a role added to models.py shows up in every
# role-parameterized test automatically.
from models import ROLES  # noqa: E402

PASSWORD = 'Testpass-2026-secure'


def _read_policy(relative_path):
    with open(os.path.join(POLICY_DIR, relative_path), encoding='utf-8', errors='replace') as handle:
        return handle.read()


@pytest.fixture(autouse=True)
def _reset_process_global_counters():
    """Clear the module-level throttling counters before and after each test.

    `_attempts` and `_memory_counters` live in module globals on purpose (that is
    what makes them work across requests in one process), which also makes them
    leak across tests in one pytest process: a lockout triggered by an earlier
    test's failed logins made a later, unrelated test's successful login return
    429. Isolation here is the cheap fix; the alternative was one app per process.
    """
    from security import _attempts, _memory_counters

    _attempts._failures.clear()
    _memory_counters._hits.clear()
    yield
    _attempts._failures.clear()
    _memory_counters._hits.clear()


@pytest.fixture(scope='session')
def policy_dir():
    """`backend/policies/` — the validation corpus the project report cites."""
    return pathlib.Path(POLICY_DIR)


@pytest.fixture
def app_dirs(tmp_path, monkeypatch):
    """Isolated upload/report folders for one test."""
    uploads = tmp_path / 'uploads'
    reports = tmp_path / 'reports'
    uploads.mkdir()
    reports.mkdir()
    monkeypatch.setattr(Config, 'UPLOAD_FOLDER', str(uploads), raising=True)
    monkeypatch.setattr(Config, 'REPORT_FOLDER', str(reports), raising=True)
    return {'uploads': uploads, 'reports': reports, 'root': tmp_path}


@pytest.fixture
def app(app_dirs):
    """A fully-wired application on a throwaway database."""
    from app import create_app

    db_path = app_dirs['root'] / 'test.db'
    instance_dir = app_dirs['root'] / 'instance'
    instance_dir.mkdir()
    application = create_app({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': f'sqlite:///{db_path}',
        'SQLALCHEMY_ENGINE_OPTIONS': {},
        'SECRET_KEY': 'a1' * 24,
        'JWT_SECRET_KEY': 'b2' * 24,
        'ENVIRONMENT': 'test',
        'INSTANCE_PATH': str(instance_dir),
        'RATE_LIMIT_ENABLED': False,
        'MONITORING_SCHEDULER_ENABLED': False,
        'JWT_ACCESS_TOKEN_EXPIRES': 3600,
        'JWT_REFRESH_TOKEN_EXPIRES': 7 * 24 * 3600,
    })
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
    # No drop_all(): the database file is inside `tmp_path` and is discarded with
    # it, and dropping trips an SAWarning because assessments and vendors
    # legitimately reference each other (a cycle SQLAlchemy cannot sort for
    # DROP on SQLite). Leaving the teardown to the temp dir is both quieter and
    # faster, and it cannot mask a teardown-order bug in the models.


@pytest.fixture
def client(app):
    return app.test_client()


# ── Accounts and organizations ──────────────────────────────────────────────

@pytest.fixture
def org_a(app, client):
    """First registered user of an org is its admin — that is the real path,
    so testing through it also pins that behaviour."""
    response = client.post('/api/auth/register', json={
        'org_name': 'Acme Analytics', 'name': 'Ada Admin',
        'email': 'ada@acme.test', 'password': PASSWORD,
    })
    assert response.status_code == 201, response.get_json()
    return {'id': response.get_json()['organization']['id'],
            'admin_id': response.get_json()['user']['id'],
            'token': response.get_json()['access_token'],
            'email': 'ada@acme.test'}


@pytest.fixture
def org_b(app, client):
    """A second, unrelated tenant for cross-org isolation tests."""
    response = client.post('/api/auth/register', json={
        'org_name': 'Betula Ltd', 'name': 'Bea Admin',
        'email': 'bea@betula.test', 'password': PASSWORD,
    })
    assert response.status_code == 201, response.get_json()
    return {'id': response.get_json()['organization']['id'],
            'token': response.get_json()['access_token'],
            'admin_id': response.get_json()['user']['id']}


def _make_user(app, org_id, name, email, role, password=PASSWORD):
    from models import User

    user = User(org_id=org_id, name=name, email=email, role=role,
                must_change_password=False)
    user.set_password(password)
    with app.app_context():
        db.session.add(user)
        db.session.commit()
        db.session.refresh(user)
    return user


@pytest.fixture
def users(app, org_a):
    """One account per role, so RBAC tests can be written as a loop instead of
    a copy-paste block per role."""
    created = {}
    for role in ROLES:
        email = f'{role}@acme.test'
        created[role] = _make_user(app, org_a['id'], role.replace('_', ' ').title(), email, role)
    return created


@pytest.fixture
def tokens(app, users):
    """A login token per role. Login is used rather than direct token creation so
    the tests also cover the real credential path."""
    out = {}
    for role, user in users.items():
        response = app.test_client().post('/api/auth/login',
                                        json={'email': user.email, 'password': PASSWORD})
        assert response.status_code == 200, response.get_json()
        out[role] = response.get_json()['access_token']
    return out


@pytest.fixture
def auth(org_a):
    """Header for the org admin."""
    return {'Authorization': f"Bearer {org_a['token']}"}


def auth_header(token):
    return {'Authorization': f'Bearer {token}'}


# ── Domain data ─────────────────────────────────────────────────────────────

@pytest.fixture
def scan_fixture(client, auth):
    """One real scan of the compliant DPDPA policy, through the upload endpoint,
    so everything downstream sits on persisted assessments/control results."""
    import io

    data = _read_policy('compliant/Fully_Compliant_Policy.txt')
    body = {'framework': 'dpdpa'}
    result = client.post('/api/scan', data={
        'file': (io.BytesIO(data.encode('utf-8')), 'Fully_Compliant_Policy.txt'),
        **body,
    }, headers=auth, content_type='multipart/form-data')
    assert result.status_code == 200, result.get_json()
    payload = result.get_json()
    return {
        'assessment_id': payload['assessment_id'],
        'report_id': payload['report_id'],
        'overall_score': payload['overall_score'],
        'controls': payload['controls'],
        'text': data,
    }


@pytest.fixture
def second_scan_fixture(client, auth):
    """A deliberately weak document for the same org, used by drift tests."""
    import io

    data = _read_policy('non_compliant/Non_Compliant_Policy.txt')
    result = client.post('/api/scan', data={
        'file': (io.BytesIO(data.encode('utf-8')), 'Non_Compliant_Policy.txt'),
    }, headers=auth, content_type='multipart/form-data')
    assert result.status_code == 200, result.get_json()
    return result.get_json()


@pytest.fixture
def vendor(client, auth):
    response = client.post('/api/vendors', json={
        'name': 'Ledgerly Processing Pvt Ltd', 'service_description': 'Payment reconciliation',
        'data_sensitivity': 'confidential', 'status': 'active',
        'contract_start': '2023-01-01', 'contract_end': '2024-01-01',
        'review_frequency_days': 365,
    }, headers=auth)
    assert response.status_code == 201, response.get_json()
    return response.get_json()['vendor']


@pytest.fixture
def watch(client, auth, scan_fixture):
    response = client.post('/api/monitoring/watches', json={
        'name': 'Privacy policy (DPDPA)',
        'filename': 'Fully_Compliant_Policy.txt',
        'framework': 'dpdpa',
        'review_interval_days': 30,
    }, headers=auth)
    assert response.status_code == 201, response.get_json()
    return response.get_json()['watch']


@pytest.fixture
def risk(client, auth):
    response = client.post('/api/risks', json={
        'title': 'Consent withdrawal not implemented in the product',
        'description': 'Policy promises a withdrawal channel the application does not provide.',
        'category': 'privacy', 'source': 'scan',
        'likelihood': 4, 'impact': 5, 'treatment': 'mitigate',
    }, headers=auth)
    assert response.status_code == 201, response.get_json()
    return response.get_json()['risk']


@pytest.fixture
def audit_with_findings(client, auth):
    response = client.post('/api/audits', json={
        'title': 'Q3 internal privacy review', 'audit_type': 'internal',
        'framework': 'dpdpa', 'status': 'in_progress',
        'planned_date': '2026-07-01', 'auditor_name': 'Internal Team',
    }, headers=auth)
    assert response.status_code == 201, response.get_json()
    audit = response.get_json()['audit']
    finding = client.post(f"/api/audits/{audit['id']}/findings", json={
        'title': 'Retention schedule incomplete', 'description': 'No deletion timeline stated.',
        'severity': 'high', 'status': 'open', 'owner': 'Privacy Office',
    }, headers=auth)
    assert finding.status_code == 201, finding.get_json()
    return {'audit': audit, 'finding': finding.get_json()['finding']}
