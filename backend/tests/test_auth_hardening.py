"""Phase 0 auth additions: self-service password reset, outbound mail, the
breached-password check, and httpOnly cookie sessions with CSRF protection."""

import hashlib
import io
import re
from datetime import datetime, timedelta

import pytest

from conftest import PASSWORD, auth_header
from extensions import db
from models import AuditTrailEvent, User


NEW_PASSWORD = 'Brand-new-passphrase-77'


# ── Password reset ──────────────────────────────────────────────────────────

def _request_reset(client, email):
    return client.post('/api/auth/request-password-reset', json={'email': email})


def _logged_reset_token(caplog):
    """With no MAIL_HOST the link is written to the log; pull the token from it."""
    match = re.search(r'/reset-password\?token=([\w\-]+)', caplog.text)
    assert match, 'no reset link was logged'
    return match.group(1)


def test_reset_response_is_identical_for_known_and_unknown_addresses(client, org_a):
    known = _request_reset(client, org_a['email'])
    unknown = _request_reset(client, 'nobody@nowhere.test')
    assert known.status_code == unknown.status_code == 200
    assert known.get_json() == unknown.get_json()


def test_reset_token_is_stored_only_as_a_hash(client, org_a, caplog):
    caplog.set_level('WARNING')
    _request_reset(client, org_a['email'])
    token = _logged_reset_token(caplog)
    user = User.query.filter_by(email=org_a['email']).first()
    assert user.password_reset_token_hash == hashlib.sha256(token.encode()).hexdigest()
    assert token not in (user.password_reset_token_hash or '')
    assert user.password_reset_expires_at > datetime.utcnow()


def test_full_reset_flow_changes_password_and_ends_old_sessions(client, org_a, caplog):
    caplog.set_level('WARNING')
    old_token = org_a['token']
    assert client.get('/api/auth/me', headers=auth_header(old_token)).status_code == 200

    _request_reset(client, org_a['email'])
    token = _logged_reset_token(caplog)
    done = client.post('/api/auth/reset-password', json={'token': token, 'new_password': NEW_PASSWORD})
    assert done.status_code == 200, done.get_json()

    # New password works, old one doesn't, the pre-reset session is dead.
    assert client.post('/api/auth/login', json={'email': org_a['email'], 'password': NEW_PASSWORD}).status_code == 200
    assert client.post('/api/auth/login', json={'email': org_a['email'], 'password': PASSWORD}).status_code == 401
    assert client.get('/api/auth/me', headers=auth_header(old_token)).status_code == 401


def test_reset_token_is_single_use(client, org_a, caplog):
    caplog.set_level('WARNING')
    _request_reset(client, org_a['email'])
    token = _logged_reset_token(caplog)
    assert client.post('/api/auth/reset-password', json={'token': token, 'new_password': NEW_PASSWORD}).status_code == 200
    again = client.post('/api/auth/reset-password', json={'token': token, 'new_password': 'Another-long-pass-88'})
    assert again.status_code == 400


def test_expired_reset_token_is_rejected(client, org_a, caplog):
    caplog.set_level('WARNING')
    _request_reset(client, org_a['email'])
    token = _logged_reset_token(caplog)
    user = User.query.filter_by(email=org_a['email']).first()
    user.password_reset_expires_at = datetime.utcnow() - timedelta(minutes=1)
    db.session.commit()
    assert client.post('/api/auth/reset-password', json={'token': token, 'new_password': NEW_PASSWORD}).status_code == 400


@pytest.mark.parametrize('payload', [
    {'token': '', 'new_password': NEW_PASSWORD},
    {'token': 'not-a-real-token', 'new_password': NEW_PASSWORD},
    {'new_password': NEW_PASSWORD},
])
def test_bad_reset_tokens_are_rejected(client, org_a, payload):
    assert client.post('/api/auth/reset-password', json=payload).status_code == 400


def test_reset_enforces_the_password_policy(client, org_a, caplog):
    caplog.set_level('WARNING')
    _request_reset(client, org_a['email'])
    token = _logged_reset_token(caplog)
    weak = client.post('/api/auth/reset-password', json={'token': token, 'new_password': 'short'})
    assert weak.status_code == 400
    # A rejected attempt must not burn the token.
    assert client.post('/api/auth/reset-password', json={'token': token, 'new_password': NEW_PASSWORD}).status_code == 200


def test_reset_clears_a_login_lockout(client, org_a, caplog):
    caplog.set_level('WARNING')
    for _ in range(12):
        client.post('/api/auth/login', json={'email': org_a['email'], 'password': 'wrong-password-x'})
    assert client.post('/api/auth/login', json={'email': org_a['email'], 'password': PASSWORD}).status_code == 429
    _request_reset(client, org_a['email'])
    token = _logged_reset_token(caplog)
    client.post('/api/auth/reset-password', json={'token': token, 'new_password': NEW_PASSWORD})
    assert client.post('/api/auth/login', json={'email': org_a['email'], 'password': NEW_PASSWORD}).status_code == 200


def test_deactivated_accounts_get_no_reset_link(client, org_a, users, caplog):
    caplog.set_level('WARNING')
    # `users` holds detached objects from another session; re-query to persist.
    User.query.filter_by(email=users['member'].email).first().is_active = False
    db.session.commit()
    _request_reset(client, users['member'].email)
    assert '/reset-password?token=' not in caplog.text


def test_reset_request_is_rate_limited(app, client, org_a):
    app.config.update(RATE_LIMIT_ENABLED=True, RATE_LIMIT_PASSWORD_RESET='2 per hour')
    codes = [_request_reset(client, f'u{i}@nowhere.test').status_code for i in range(4)]
    assert codes[:2] == [200, 200] and 429 in codes[2:]


def test_reset_request_and_completion_are_audited(client, org_a, caplog):
    caplog.set_level('WARNING')
    _request_reset(client, org_a['email'])
    token = _logged_reset_token(caplog)
    client.post('/api/auth/reset-password', json={'token': token, 'new_password': NEW_PASSWORD})
    actions = {e.action for e in AuditTrailEvent.query.filter_by(org_id=org_a['id'])}
    assert {'auth.password_reset_requested', 'auth.password_reset'} <= actions
    # The raw token must never reach the trail.
    assert all(token not in str(e.detail) and token not in str(e.summary)
               for e in AuditTrailEvent.query.filter_by(org_id=org_a['id']))


# ── Outbound mail ───────────────────────────────────────────────────────────

class FakeSMTP:
    instances = []

    def __init__(self, host, port, timeout=None, context=None):
        self.host, self.port, self.calls, self.sent = host, port, [], []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self, context=None):
        self.calls.append('starttls')

    def login(self, user, password):
        self.calls.append(('login', user, password))

    def send_message(self, message):
        self.sent.append(message)


def test_mail_is_sent_through_smtp_when_configured(app, client, org_a, monkeypatch):
    FakeSMTP.instances.clear()
    monkeypatch.setattr('smtplib.SMTP', FakeSMTP)
    app.config.update(MAIL_HOST='smtp.test', MAIL_PORT=2525, MAIL_USERNAME='u', MAIL_PASSWORD='p',
                      MAIL_FROM='audinexia@example.test', APP_BASE_URL='https://grc.example.test')
    _request_reset(client, org_a['email'])
    smtp = FakeSMTP.instances[0]
    assert (smtp.host, smtp.port) == ('smtp.test', 2525)
    assert smtp.calls == ['starttls', ('login', 'u', 'p')]
    message = smtp.sent[0]
    assert message['To'] == org_a['email'] and message['From'] == 'audinexia@example.test'
    assert 'https://grc.example.test/reset-password?token=' in message.get_content()
    event = AuditTrailEvent.query.filter_by(action='auth.password_reset_requested').first()
    assert event.detail['email_delivered'] is True


def test_smtp_failure_is_swallowed_and_reported_as_not_delivered(app, client, org_a, monkeypatch):
    class Boom(FakeSMTP):
        def send_message(self, message):
            raise OSError('connection refused')

    monkeypatch.setattr('smtplib.SMTP', Boom)
    app.config.update(MAIL_HOST='smtp.test')
    response = _request_reset(client, org_a['email'])
    assert response.status_code == 200          # never leaks the failure to the caller
    event = AuditTrailEvent.query.filter_by(action='auth.password_reset_requested').first()
    assert event.detail['email_delivered'] is False


# ── Breached-password check ─────────────────────────────────────────────────

class FakeResponse:
    status = 200

    def __init__(self, body):
        self._body = body.encode()

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _stub_hibp(monkeypatch, password, count=12345):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    body = f'0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n{sha1[5:]}:{count}\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:3'
    seen = {}

    def fake_urlopen(request_obj, timeout=None):
        seen['url'] = request_obj.full_url
        return FakeResponse(body)

    monkeypatch.setattr('urllib.request.urlopen', fake_urlopen)
    return seen, sha1


def test_breached_password_is_rejected_and_only_a_hash_prefix_is_sent(app, client, monkeypatch):
    app.config['HIBP_CHECK_ENABLED'] = True
    seen, sha1 = _stub_hibp(monkeypatch, NEW_PASSWORD)
    response = client.post('/api/auth/register', json={
        'org_name': 'Breach Co', 'name': 'B', 'email': 'b@breach.test', 'password': NEW_PASSWORD})
    assert response.status_code == 400 and 'breach' in response.get_json()['error']
    assert seen['url'].endswith('/range/' + sha1[:5])
    assert sha1[5:] not in seen['url']


def test_breach_check_fails_open_when_the_service_is_unreachable(app, client, monkeypatch):
    import urllib.error

    app.config['HIBP_CHECK_ENABLED'] = True

    def down(*args, **kwargs):
        raise urllib.error.URLError('no network')

    monkeypatch.setattr('urllib.request.urlopen', down)
    response = client.post('/api/auth/register', json={
        'org_name': 'Offline Co', 'name': 'O', 'email': 'o@offline.test', 'password': NEW_PASSWORD})
    assert response.status_code == 201


def test_breach_check_covers_change_password_and_admin_created_accounts(app, client, org_a, monkeypatch):
    app.config['HIBP_CHECK_ENABLED'] = True
    _stub_hibp(monkeypatch, NEW_PASSWORD)
    headers = auth_header(org_a['token'])
    assert client.post('/api/auth/change-password', headers=headers,
                       json={'current_password': PASSWORD, 'new_password': NEW_PASSWORD}).status_code == 400
    assert client.post('/api/admin/users', headers=headers, json={
        'email': 'new@acme.test', 'name': 'New', 'temp_password': NEW_PASSWORD, 'role': 'member'}).status_code == 400


# ── Cookie sessions ─────────────────────────────────────────────────────────

COOKIE_MODE = {'X-Session-Mode': 'cookie'}


def _cookie_login(app, email, password=PASSWORD):
    client = app.test_client()
    response = client.post('/api/auth/login', json={'email': email, 'password': password}, headers=COOKIE_MODE)
    assert response.status_code == 200, response.get_json()
    return client, response


def test_dashboard_mode_keeps_tokens_out_of_the_response_body(app, org_a):
    _, response = _cookie_login(app, org_a['email'])
    body = response.get_json()
    assert 'access_token' not in body and 'refresh_token' not in body and body['user']['email'] == org_a['email']


def test_api_clients_still_receive_bearer_tokens(client, org_a):
    body = client.post('/api/auth/login', json={'email': org_a['email'], 'password': PASSWORD}).get_json()
    assert body['access_token'] and body['refresh_token']


def test_session_cookies_are_httponly_samesite_strict_and_secure(app, org_a):
    _, response = _cookie_login(app, org_a['email'])
    cookies = {c.split('=', 1)[0]: c for c in response.headers.getlist('Set-Cookie')}
    for name in ('access_token_cookie', 'refresh_token_cookie'):
        assert 'HttpOnly' in cookies[name] and 'SameSite=Strict' in cookies[name] and 'Secure' in cookies[name]
    # The CSRF double-submit cookies are the ones JS must be able to read.
    assert 'HttpOnly' not in cookies['csrf_access_token']
    assert 'Path=/api/auth/refresh' in cookies['refresh_token_cookie']


def _jar_client(app, email):
    """A client that behaves like a browser on https (Secure cookies are sent)."""
    client = app.test_client()
    client.post('/api/auth/login', json={'email': email, 'password': PASSWORD}, headers=COOKIE_MODE,
                base_url='https://localhost')
    return client


def test_cookie_authenticated_writes_require_the_csrf_header(app, org_a):
    client = _jar_client(app, org_a['email'])
    assert client.get('/api/risks', base_url='https://localhost').status_code == 200   # reads need no CSRF
    body = {'description': 'x', 'likelihood': 2, 'impact': 2}
    assert client.post('/api/risks', json=body, base_url='https://localhost').status_code == 401
    assert client.post('/api/risks', json=body, base_url='https://localhost',
                       headers={'X-CSRF-TOKEN': 'wrong'}).status_code == 401
    csrf = client.get_cookie('csrf_access_token', domain='localhost').value
    ok = client.post('/api/risks', json=body, base_url='https://localhost', headers={'X-CSRF-TOKEN': csrf})
    assert ok.status_code == 201, ok.get_json()


def test_bearer_requests_are_not_subject_to_csrf(client, org_a):
    response = client.post('/api/risks', headers=auth_header(org_a['token']),
                           json={'description': 'x', 'likelihood': 2, 'impact': 2})
    assert response.status_code == 201


def test_logout_clears_cookies_and_revokes_the_session(app, org_a):
    client = _jar_client(app, org_a['email'])
    csrf = client.get_cookie('csrf_access_token', domain='localhost').value
    out = client.post('/api/auth/logout', base_url='https://localhost', headers={'X-CSRF-TOKEN': csrf})
    assert out.status_code == 200
    cleared = ' '.join(out.headers.getlist('Set-Cookie'))
    assert 'access_token_cookie=;' in cleared and 'refresh_token_cookie=;' in cleared
    assert client.get('/api/auth/me', base_url='https://localhost').status_code == 401


def test_silent_refresh_with_the_refresh_cookie(app, org_a):
    client = _jar_client(app, org_a['email'])
    csrf_refresh = client.get_cookie('csrf_refresh_token', domain='localhost').value
    response = client.post('/api/auth/refresh', base_url='https://localhost', headers={'X-CSRF-TOKEN': csrf_refresh})
    assert response.status_code == 200
    assert 'access_token' not in response.get_json() or response.get_json().get('access_token')
    assert any('access_token_cookie=' in c for c in response.headers.getlist('Set-Cookie'))
    # Without the CSRF header the refresh is refused.
    assert client.post('/api/auth/refresh', base_url='https://localhost').status_code == 401
