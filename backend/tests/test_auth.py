"""Authentication, session lifecycle and password policy."""

import pytest

from conftest import PASSWORD, auth_header

from models import User, db


# ── Registration ────────────────────────────────────────────────────────────

def test_register_creates_org_and_admin_role(client):
    response = client.post('/api/auth/register', json={
        'org_name': 'New Tenant', 'name': 'Founder', 'email': 'founder@new.test',
        'password': PASSWORD,
    })
    assert response.status_code == 201
    body = response.get_json()
    assert body['user']['role'] == 'org_admin'
    # Self-registration already knows the user's password, so there is nothing to
    # force them to change.
    assert body['user']['must_change_password'] is False
    assert body['organization']['name'] == 'New Tenant'
    assert body['access_token'] and body['refresh_token']


@pytest.mark.parametrize('missing', ['org_name', 'name', 'email', 'password'])
def test_register_requires_every_field(client, missing):
    payload = {'org_name': 'A', 'name': 'B', 'email': 'c@d.test', 'password': PASSWORD}
    del payload[missing]
    response = client.post('/api/auth/register', json=payload)
    assert response.status_code == 400
    assert missing in response.get_json()['error']


def test_register_rejects_malformed_email(client):
    response = client.post('/api/auth/register', json={
        'org_name': 'A', 'name': 'B', 'email': 'not-an-email', 'password': PASSWORD,
    })
    assert response.status_code == 400
    assert 'valid' in response.get_json()['error']


def test_register_rejects_weak_password_and_lists_problems(client):
    response = client.post('/api/auth/register', json={
        'org_name': 'A', 'name': 'B', 'email': 'weak@x.test', 'password': 'abc',
    })
    assert response.status_code == 400
    body = response.get_json()
    assert body['problems'], 'the response must say what is wrong, not just "weak"'
    assert any('long' in problem or 'character' in problem for problem in body['problems'])


def test_register_is_case_insensitive_on_email(client):
    client.post('/api/auth/register', json={
        'org_name': 'A', 'name': 'B', 'email': 'Dup@X.test', 'password': PASSWORD,
    })
    response = client.post('/api/auth/register', json={
        'org_name': 'A', 'name': 'C', 'email': 'dup@x.test', 'password': PASSWORD,
    })
    assert response.status_code == 409
    assert 'already registered' in response.get_json()['error'].lower()


def test_password_policy_endpoint_advertises_the_real_rules(client):
    from config import Config

    response = client.get('/api/auth/password-policy')
    assert response.status_code == 200
    body = response.get_json()
    assert body['min_length'] == Config.MIN_PASSWORD_LENGTH
    assert isinstance(body['rules'], list) and body['rules']


# ── Login ───────────────────────────────────────────────────────────────────

def test_login_returns_tokens_and_identity(client, org_a):
    response = client.post('/api/auth/login', json={'email': org_a['email'], 'password': PASSWORD})
    assert response.status_code == 200
    body = response.get_json()
    assert body['access_token'] and body['refresh_token']
    assert body['user']['id'] == org_a['admin_id']
    assert body['password_change_required'] is False


def test_login_stamps_last_login(client, org_a):
    client.post('/api/auth/login', json={'email': org_a['email'], 'password': PASSWORD})
    with client.application.app_context():
        assert db.session.get(User, org_a['admin_id']).last_login_at is not None


def test_unknown_email_and_wrong_password_are_indistinguishable(client, org_a):
    """Same status, same message, same shape — otherwise the endpoint is an
    account enumeration oracle."""
    unknown = client.post('/api/auth/login', json={'email': 'nobody@nowhere.test',
                                                    'password': PASSWORD})
    wrong = client.post('/api/auth/login', json={'email': org_a['email'],
                                                 'password': 'WrongPassword-123!'})
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.get_json()['error'] == wrong.get_json()['error']
    assert unknown.get_json()['code'] == wrong.get_json()['code'] == 'invalid_credentials'


def test_deactivated_account_gets_a_distinct_actionable_message(client, app, org_a, users):
    """Deliberate asymmetry with the 401 above: an inactive account is safe to
    describe to the person who just typed its credentials, and telling them is
    what gets them to contact an admin instead of retrying all day."""
    target = users['read_only']
    with app.app_context():
        db.session.get(User, target.id).is_active = False
        db.session.commit()
    response = client.post('/api/auth/login', json={'email': target.email, 'password': PASSWORD})
    assert response.status_code == 403
    assert response.get_json()['code'] == 'account_inactive'


def test_login_throttles_repeated_failures(client, app, org_a, monkeypatch):
    # Tunables are patched on app.config, which is what the security controls
    # read through security._setting.
    monkeypatch.setitem(app.config, 'LOGIN_MAX_ATTEMPTS', 3)
    monkeypatch.setitem(app.config, 'LOGIN_LOCKOUT_MINUTES', 5)
    from security import clear_login_failures

    clear_login_failures(org_a['email'])
    for _ in range(3):
        client.post('/api/auth/login', json={'email': org_a['email'], 'password': 'Nope-1234567!x'})
    response = client.post('/api/auth/login', json={'email': org_a['email'], 'password': PASSWORD})
    assert response.status_code == 429, response.get_json()
    body = response.get_json()
    assert body['code'] == 'account_locked'
    assert body['retry_after_seconds'] > 0
    assert response.headers.get('Retry-After')


def test_successful_login_clears_the_failure_counter(client, app, org_a, monkeypatch):
    monkeypatch.setitem(app.config, 'LOGIN_MAX_ATTEMPTS', 3)
    from security import clear_login_failures

    clear_login_failures(org_a['email'])
    for _ in range(2):
        client.post('/api/auth/login', json={'email': org_a['email'], 'password': 'Nope-1234567!x'})
    assert client.post('/api/auth/login', json={'email': org_a['email'],
                                                'password': PASSWORD}).status_code == 200
    # A later single mistake must not be locked out by the pre-success attempts.
    response = client.post('/api/auth/login', json={'email': org_a['email'],
                                                     'password': 'Nope-1234567!x'})
    assert response.status_code == 401, response.get_json()


# ── Tokens ──────────────────────────────────────────────────────────────────

def test_protected_route_needs_a_token(client):
    assert client.get('/api/assessments').status_code == 401


def test_garbage_token_is_rejected(client):
    response = client.get('/api/assessments', headers=auth_header('not.a.jwt'))
    assert response.status_code in (401, 422)


def test_me_reports_identity_and_expiry(client, auth):
    response = client.get('/api/auth/me', headers=auth)
    assert response.status_code == 200
    body = response.get_json()
    assert body['user']['role'] == 'org_admin'
    assert body['token_expires_in_minutes'] >= 1


def test_refresh_exchanges_refresh_token_for_access_token(client, org_a):
    login = client.post('/api/auth/login', json={'email': org_a['email'], 'password': PASSWORD})
    refresh_token = login.get_json()['refresh_token']
    response = client.post('/api/auth/refresh', headers=auth_header(refresh_token))
    assert response.status_code == 200
    assert response.get_json()['access_token']


def test_access_token_cannot_be_used_to_refresh(client, auth):
    """Type confusion: an access token must not mint fresh sessions forever."""
    response = client.post('/api/auth/refresh', headers=auth)
    assert response.status_code in (401, 422)


def test_logout_revokes_the_refresh_token(client, org_a):
    login = client.post('/api/auth/login', json={'email': org_a['email'], 'password': PASSWORD})
    tokens = login.get_json()
    response = client.post('/api/auth/logout', headers=auth_header(tokens['access_token']),
                           json={'refresh_token': tokens['refresh_token']})
    assert response.status_code == 200
    after = client.post('/api/auth/refresh', headers=auth_header(tokens['refresh_token']))
    assert after.status_code in (401, 422), 'a revoked refresh token must not mint access tokens'


# ── Password change ─────────────────────────────────────────────────────────

def test_change_password_wrong_current_is_rejected(client, auth):
    response = client.post('/api/auth/change-password', headers=auth,
                           json={'current_password': 'NotIt-12345678', 'new_password': 'Brandnew-Pass-99'})
    assert response.status_code == 400
    assert 'incorrect' in response.get_json()['error'].lower()


def test_change_password_rejects_reusing_the_current_password(client, auth):
    response = client.post('/api/auth/change-password', headers=auth,
                           json={'current_password': PASSWORD, 'new_password': PASSWORD})
    assert response.status_code == 400
    assert 'differ' in response.get_json()['error'].lower()


def test_change_password_rejects_weak_new_password(client, auth):
    response = client.post('/api/auth/change-password', headers=auth,
                           json={'current_password': PASSWORD, 'new_password': 'short'})
    assert response.status_code == 400
    assert response.get_json()['problems']


def test_change_password_invalidates_previously_issued_tokens(client, org_a):
    """The "sign out everywhere" property of a password change, which is why an
    admin can reset a compromised account meaningfully."""
    login = client.post('/api/auth/login', json={'email': org_a['email'], 'password': PASSWORD})
    tokens = login.get_json()
    headers = auth_header(tokens['access_token'])
    assert client.get('/api/auth/me', headers=headers).status_code == 200

    changed = client.post('/api/auth/change-password', headers=headers,
                          json={'current_password': PASSWORD, 'new_password': 'Brandnew-Pass-99'})
    assert changed.status_code == 200
    assert changed.get_json()['sessions_invalidated'] is True

    assert client.get('/api/auth/me', headers=headers).status_code in (401, 422)
    refresh = client.post('/api/auth/refresh', headers=auth_header(tokens['refresh_token']))
    assert refresh.status_code in (401, 422)

    relogin = client.post('/api/auth/login', json={'email': org_a['email'],
                                                    'password': 'Brandnew-Pass-99'})
    assert relogin.status_code == 200


# ── Forced change (admin-set temp password) ─────────────────────────────────

def test_admin_created_account_is_locked_out_until_it_changes_its_password(client, auth, app):
    created = client.post('/api/admin/users', headers=auth, json={
        'name': 'Temp Person', 'email': 'temp@acme.test', 'role': 'auditor',
        'temp_password': 'Temppass-2026-aa',
    })
    assert created.status_code == 201
    assert created.get_json()['user']['must_change_password'] is True

    login = client.post('/api/auth/login', json={'email': 'temp@acme.test',
                                                 'password': 'Temppass-2026-aa'})
    assert login.status_code == 200
    assert login.get_json()['password_change_required'] is True
    headers = auth_header(login.get_json()['access_token'])

    for path in ('/api/assessments', '/api/vendors', '/api/risks', '/api/admin/settings'):
        blocked = client.get(path, headers=headers)
        assert blocked.status_code == 403, f'{path} must refuse a flagged account'
        assert blocked.get_json()['code'] == 'password_change_required'
        assert 'change-password' in blocked.get_json()['error']

    # The escape hatch must stay reachable, or the gate is a lockout.
    assert client.get('/api/auth/me', headers=headers).status_code == 200
    assert client.get('/api/auth/password-policy').status_code == 200
    changed = client.post('/api/auth/change-password', headers=headers,
                          json={'current_password': 'Temppass-2026-aa',
                                'new_password': 'Chosenpass-2026-zz'})
    assert changed.status_code == 200

    new_login = client.post('/api/auth/login', json={'email': 'temp@acme.test',
                                                      'password': 'Chosenpass-2026-zz'})
    assert new_login.get_json()['password_change_required'] is False
    assert client.get('/api/assessments',
                      headers=auth_header(new_login.get_json()['access_token'])).status_code == 200


def test_ops_endpoints_stay_open_while_a_password_change_is_pending(client, auth):
    """/healthz is polled by an orchestrator that has no user context; the gate
    must apply to tenant data, not to liveness."""
    created = client.post('/api/admin/users', headers=auth, json={
        'name': 'Temp Two', 'email': 'temp2@acme.test', 'role': 'member',
        'temp_password': 'Temppass-2026-bb',
    })
    assert created.status_code == 201
    assert client.get('/healthz').status_code == 200
    assert client.get('/readyz').status_code == 200


def test_admin_password_reset_rearms_the_forced_change(client, auth, app, users):
    target = users['member']
    response = client.post(f"/api/admin/users/{target.id}/password", headers=auth,
                           json={'new_password': 'Resetpass-2026-qq'})
    assert response.status_code == 200
    with app.app_context():
        assert db.session.get(User, target.id).must_change_password is True
    login = client.post('/api/auth/login', json={'email': target.email,
                                                 'password': 'Resetpass-2026-qq'})
    assert login.get_json()['password_change_required'] is True


def test_rate_limiter_can_share_counters_through_the_database(app, client, org_a, monkeypatch):
    """The in-memory limiter is per-process; RATE_LIMIT_STORE=db exists for
    multi-worker deployments and must actually count across requests."""
    monkeypatch.setitem(app.config, 'RATE_LIMIT_ENABLED', True)
    monkeypatch.setitem(app.config, 'RATE_LIMIT_STORE', 'db')
    with app.app_context():
        from security import check_rate_limit

        allowed = [check_rate_limit('scope:test', '3 per minute', identity=org_a['admin_id'])[0]
                   for _ in range(4)]
    assert allowed == [True, True, True, False]
