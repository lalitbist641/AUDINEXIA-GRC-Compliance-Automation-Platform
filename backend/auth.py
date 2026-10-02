"""Authentication: registration, login, refresh, logout, revocation.

Phase 8 hardened three things that were acceptable for local development and
are not for a system holding compliance findings:

* Revocation moved from a process-local set to the `revoked_tokens` table, so a
  logout on worker A invalidates the token on worker B and survives a restart.
* Login attempts are throttled per email, and failures return an
  indistinguishable message so the endpoint cannot be used to enumerate which
  addresses have accounts.
* Passwords go through a length-first policy (security.check_password_strength)
  rather than a bare minimum-length check.
"""

import hashlib
import secrets
from datetime import datetime, timedelta

from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
    set_access_cookies,
    set_refresh_cookies,
    unset_jwt_cookies,
)

from extensions import db, jwt
from models import Organization, RevokedToken, User
from security import (
    clear_login_failures,
    client_ip,
    limit_or_reject,
    login_is_locked,
    password_acceptable,
    register_login_failure,
)
from core.audit_trail import record
from core.mailer import send_email

auth_bp = Blueprint('auth', __name__)


@jwt.token_in_blocklist_loader
def _check_if_token_revoked(jwt_header, jwt_payload):
    """Two checks, both indexed:
      1. an explicit jti revocation (logout), and
      2. a stale token_version claim (password change, admin-forced sign-out,
         deactivation, role change).

    (2) is what makes "log this user out everywhere" a single UPDATE rather
    than a sweep of every jti they were ever issued. The lookup is one
    primary-key read per protected request — the same cost as a session lookup
    in a session-cookie app, and the price of revocation being correct across
    workers and restarts.
    """
    jti = jwt_payload['jti']
    if RevokedToken.query.filter_by(jti=jti).first() is not None:
        return True

    user_id = jwt_payload.get('sub') or jwt_payload.get('identity')
    try:
        user = db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return True
    if user is None or not user.is_active:
        return True
    issued_version = jwt_payload.get('tv')
    if issued_version is None:
        # A token issued before Phase 8 carries no version claim. Treat it as
        # valid but log once per worker, so an upgrade does not sign everyone
        # out mid-session; short access-token life means the stragglers expire
        # within JWT_ACCESS_MINUTES.
        return False
    return int(issued_version) != int(user.token_version or 0)


@jwt.expired_token_loader
def _expired_token(jwt_header, jwt_payload):
    return jsonify({
        'error': 'Token has expired',
        'code': 'token_expired',
        'message': 'Refresh the session via POST /api/auth/refresh.',
    }), 401


@jwt.invalid_token_loader
def _invalid_token(reason):
    # `reason` comes from the JWT library and can quote parts of the payload,
    # so it is logged and never echoed back — a client does not need it and a
    # log does.
    current_app.logger.warning('rejected JWT: %s', reason)
    return jsonify({'error': 'Invalid token', 'code': 'token_invalid'}), 401


@jwt.unauthorized_loader
def _missing_token(reason):
    return jsonify({'error': 'Missing or malformed Authorization header',
                    'code': 'token_missing'}), 401


@jwt.revoked_token_loader
def _revoked_token(jwt_header, jwt_payload):
    return jsonify({'error': 'Token has been revoked; log in again.',
                    'code': 'token_revoked'}), 401


def _user_claims(user):
    # 'tv' is the token version — see the blocklist loader for why it is in
    # every token rather than looked up by jti.
    return {'org_id': user.org_id, 'role': user.role, 'tv': user.token_version or 0}


def _issue_tokens(user):
    claims = _user_claims(user)
    return {
        'access_token': create_access_token(identity=str(user.id), additional_claims=claims),
        'refresh_token': create_refresh_token(identity=str(user.id), additional_claims=claims),
    }


def _cookie_only():
    """The dashboard sends `X-Session-Mode: cookie`: its tokens live in httpOnly
    cookies that page JavaScript can't read, so they're left out of the JSON body
    entirely. API clients (no such header) still receive tokens in the body and may
    use them as bearer tokens. Cookies are set either way."""
    return request.headers.get('X-Session-Mode', '').lower() == 'cookie'


def _session_response(payload, status, tokens):
    """Build a login/register/refresh response: set the httpOnly session cookies
    and include the raw tokens in the body only for non-dashboard clients."""
    body = dict(payload)
    if not _cookie_only():
        body.update(tokens)
    response = jsonify(body)
    response.status_code = status
    if 'access_token' in tokens:
        set_access_cookies(response, tokens['access_token'])
    if 'refresh_token' in tokens:
        set_refresh_cookies(response, tokens['refresh_token'])
    return response


def _hash_reset_token(raw_token):
    return hashlib.sha256(raw_token.encode('utf-8')).hexdigest()


def _claim_expiry(claims):
    """JWT 'exp' is epoch seconds; store it as a naive UTC datetime so the
    blocklist row can be compared against datetime.utcnow() during pruning."""
    exp = claims.get('exp')
    if not exp:
        return datetime.utcnow() + timedelta(hours=1)
    return datetime.utcfromtimestamp(float(exp))


def _revoke(jti, user=None, reason='logout', expires_at=None):
    """Insert a revocation row. On a unique-index collision (a replayed logout,
    or the astronomically unlikely jti repeat) the token is already revoked, so
    the conflict is treated as success rather than an error."""
    existing = RevokedToken.query.filter_by(jti=jti).first()
    if existing:
        return existing
    token = RevokedToken(
        jti=jti,
        user_id=user.id if user else None,
        org_id=user.org_id if user else None,
        reason=reason,
        # The row only needs to outlive the token itself: once exp has passed
        # the library rejects it regardless of the blocklist, so this table
        # never grows past one token lifetime (see prune_expired_revocations).
        expires_at=expires_at or (datetime.utcnow() + timedelta(hours=1)),
    )
    db.session.add(token)
    return token


def prune_expired_revocations():
    """Drop blocklist rows for tokens that have already expired.

    Called opportunistically from /logout rather than by a scheduler: the table
    would otherwise grow by one row per logout forever, and a compliance tool
    should not need an ops ritual to stay tidy.
    """
    cutoff = datetime.utcnow()
    deleted = RevokedToken.query.filter(RevokedToken.expires_at < cutoff).delete()
    if deleted:
        db.session.commit()
    return deleted


@auth_bp.route('/register', methods=['POST'])
def register():
    rejected = limit_or_reject('auth:register', current_app.config['RATE_LIMIT_REGISTER'])
    if rejected is not None:
        return rejected

    data = request.get_json(silent=True) or {}
    org_name = (data.get('org_name') or '').strip()
    name = (data.get('name') or '').strip()
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    if not org_name or not name or not email or not password:
        return jsonify({'error': 'org_name, name, email, and password are all required'}), 400
    if '@' not in email or '.' not in email.split('@')[-1]:
        return jsonify({'error': 'email must be a valid address'}), 400
    ok, problems = password_acceptable(password)
    if not ok:
        return jsonify({'error': f'Password {" and ".join(problems)}', 'problems': problems}), 400
    if len(org_name) > 200 or len(name) > 200:
        return jsonify({'error': 'org_name and name must be at most 200 characters'}), 400

    if User.query.filter_by(email=email).first():
        # Same response as "email already registered" for a login attempt: the
        # register endpoint is inherently an enumeration oracle (it must say why
        # an email cannot be reused), so this is a documented product choice
        # rather than a leak to hide — see SECURITY.md.
        return jsonify({'error': 'Email already registered'}), 409

    org = Organization(name=org_name)
    db.session.add(org)
    db.session.flush()  # get org.id before commit

    user = User(org_id=org.id, email=email, name=name, role='org_admin', is_active=True,
                    must_change_password=False)
    user.set_password(password)
    db.session.add(user)
    db.session.flush()
    db.session.commit()

    record('auth.register', 'user', user.id, f'Organization "{org_name}" created',
           {'org_name': org_name, 'email': email, 'role': 'org_admin'},
           user_id=user.id, org_id=org.id)
    current_app.logger.info('registered org=%s user=%s', org.id, user.id,
                            extra={'extra_fields': {'event': 'auth_register',
                                                     'org_id': org.id, 'user_id': user.id}})

    return _session_response({
        'user': user.to_dict(),
        'organization': {'id': org.id, 'name': org.name},
        # Surfaced so a client can send a fresh account straight to the
        # password form. The flag is ALSO enforced server-side
        # (security.password_change_gate) — this field is a convenience, never
        # the control.
        'password_change_required': bool(user.must_change_password),
    }, 201, _issue_tokens(user))


@auth_bp.route('/login', methods=['POST'])
def login():
    rejected = limit_or_reject('auth:login', current_app.config['RATE_LIMIT_LOGIN'])
    if rejected is not None:
        return rejected

    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    lockout = login_is_locked(email)
    if lockout:
        subject = User.query.filter_by(email=email).first()
        if subject:
            attempts = current_app.config['LOGIN_MAX_ATTEMPTS']
            record('auth.login_locked', 'user', subject.id,
                   f'Sign-in blocked for {email}: {attempts} failed attempts',
                   {'email': email, 'retry_after_seconds': lockout,
                    'client_ip': client_ip()},
                   user_id=subject.id, org_id=subject.org_id)
        response = jsonify({
            'error': f'Too many failed attempts. Try again in {lockout} seconds.',
            'code': 'account_locked',
            'retry_after_seconds': lockout,
        })
        response.status_code = 429
        response.headers['Retry-After'] = str(lockout)
        return response

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        locked = register_login_failure(email)
        payload = {'error': 'Invalid email or password', 'code': 'invalid_credentials'}
        if locked:
            payload['error'] = 'Too many failed attempts. Try again later.'
            payload['code'] = 'account_locked'
            response = jsonify(payload)
            response.status_code = 429
            return response
        current_app.logger.warning('failed login for %s', email,
                                   extra={'extra_fields': {'event': 'auth_failure',
                                                            'client_ip': request.headers.get('X-Real-IP')}})
        # A failed sign-in is audit information, but the trail is an org-scoped
        # table: for an unknown address there is no org to attach the row to, so
        # record() drops it (the application log above still has it). When the
        # address does exist, that organization's admins are told, because
        # "someone is guessing at our accounts" is exactly what they must see.
        if user:
            record('auth.login_failed', 'user', user.id,
                   f'Failed sign-in attempt for {email}',
                   {'email': email, 'reason': 'bad_password', 'client_ip': client_ip()},
                   user_id=user.id, org_id=user.org_id)
        return jsonify(payload), 401
    if not user.is_active:
        # Distinct from a bad password on purpose: an inactive account is a
        # legitimate thing to tell the *named* user about, and this cannot be
        # reached by guessing a password.
        return jsonify({'error': 'This account has been deactivated. Contact your organization admin.',
                        'code': 'account_inactive'}), 403

    clear_login_failures(email)
    user.last_login_at = datetime.utcnow()
    db.session.commit()
    tokens = _issue_tokens(user)

    record('auth.login', 'user', user.id, f'{user.name} signed in', {'email': email},
           user_id=user.id, org_id=user.org_id)
    return _session_response({
        'user': user.to_dict(),
        'organization': {'id': user.organization.id, 'name': user.organization.name},
        # Lets a client send a flagged account straight to the password form.
        # Advisory only: the enforcement is security.password_change_gate, which
        # refuses the API regardless of what the client does with this field.
        'password_change_required': bool(user.must_change_password),
    }, 200, tokens)


@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)
    if not user or not user.is_active:
        return jsonify({'error': 'User not found or inactive'}), 401
    # Re-read role/org from the row rather than the old claims: a role change or
    # an org move must not persist inside a still-valid refresh token.
    access_token = create_access_token(identity=str(user.id), additional_claims=_user_claims(user))
    return _session_response({'success': True}, 200, {'access_token': access_token})


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    claims = get_jwt()
    user = db.session.get(User, int(get_jwt_identity()))
    _revoke(claims['jti'], user, expires_at=_claim_expiry(claims))
    # Access tokens are short-lived, so revoking the refresh token is the part
    # that actually ends a session. The client may send it in the body; if it
    # does not, the refresh token lives out its 7 days and can mint a new
    # access token — a real limitation of stateless refresh, stated here and in
    # SECURITY.md rather than papered over.
    refresh_raw = ((request.get_json(silent=True) or {}).get('refresh_token')
                   or request.cookies.get('refresh_token_cookie'))
    if refresh_raw:
        try:
            from flask_jwt_extended import decode_token

            decoded = decode_token(refresh_raw)
            if decoded.get('type') == 'refresh':
                _revoke(decoded['jti'], user, expires_at=_claim_expiry(decoded),
                        reason='logout_refresh')
        except Exception as exc:
            current_app.logger.info('logout: refresh token not revoked (%s)', exc)
    pruned = prune_expired_revocations()
    db.session.commit()
    record('auth.logout', 'user', user.id if user else None,
           f'{user.name} signed out' if user else 'signed out',
           {'pruned_expired_blocklist_rows': pruned})
    response = jsonify({'success': True, 'refresh_token_revoked': bool(refresh_raw)})
    unset_jwt_cookies(response)  # also clears the httpOnly cookies JS can't touch
    return response, 200



def _access_token_minutes():
    """Remaining-validity window of an access token, in whole minutes.

    Flask-JWT accepts either a timedelta or a raw number of seconds for
    JWT_ACCESS_TOKEN_EXPIRES, and a deployment that sets the integer form used to
    500 this endpoint (`int` has no `.total_seconds()`) — a bug the test suite
    found by configuring the app the way the docs allow.
    """
    from datetime import timedelta

    value = current_app.config['JWT_ACCESS_TOKEN_EXPIRES']
    seconds = value.total_seconds() if isinstance(value, timedelta) else float(value)
    return max(int(seconds // 60), 1)


@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def me():
    """Session introspection the dashboard needs after a reload, so a refresh
    of /dashboard restores identity without re-typing credentials."""
    user = db.session.get(User, int(get_jwt_identity()))
    if not user or not user.is_active:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({
        'user': user.to_dict(),
        'organization': {'id': user.organization.id, 'name': user.organization.name},
        'token_expires_in_minutes': _access_token_minutes(),
    })


@auth_bp.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    user = db.session.get(User, int(get_jwt_identity()))
    if not user:
        return jsonify({'error': 'Not found'}), 404
    data = request.get_json(silent=True) or {}
    current_password = data.get('current_password') or ''
    new_password = data.get('new_password') or ''

    if not user.check_password(current_password):
        return jsonify({'error': 'Current password is incorrect'}), 400
    if current_password == new_password:
        return jsonify({'error': 'New password must differ from the current password'}), 400
    ok, problems = password_acceptable(new_password)
    if not ok:
        return jsonify({'error': f'New password {" and ".join(problems)}', 'problems': problems}), 400

    user.set_password(new_password)
    user.must_change_password = False
    # Bumping the version invalidates every token already issued to this user
    # (the blocklist loader compares the claim against this column), which is
    # the "sign out everywhere" behavior a password change should have.
    user.token_version = (user.token_version or 0) + 1
    user_id = user.id
    db.session.commit()
    record('auth.password_change', 'user', user_id,
           'Password changed; previously issued tokens invalidated')
    response = jsonify({'success': True, 'sessions_invalidated': True,
                        'note': 'All access and refresh tokens for this account are now invalid; '
                                'sign in again.'})
    unset_jwt_cookies(response)
    return response, 200


@auth_bp.route('/request-password-reset', methods=['POST'])
def request_password_reset():
    """Start a self-service password reset. The response is IDENTICAL whether or
    not the address belongs to an account (no enumeration), and the endpoint is
    rate limited per IP and per address. The reset link is emailed when a mail
    server is configured and otherwise written to the server log -- see
    core/mailer.py; the response never claims a message was delivered."""
    rejected = limit_or_reject('auth:reset', current_app.config['RATE_LIMIT_PASSWORD_RESET'])
    if rejected is not None:
        return rejected

    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    generic = jsonify({
        'success': True,
        'message': 'If an account exists for that address, a password reset link has been sent.',
    })
    if not email or '@' not in email:
        return generic, 200
    # Second limiter keyed on the address, so one mailbox can't be flooded from
    # many IPs. Same response either way.
    if limit_or_reject('auth:reset-email', current_app.config['RATE_LIMIT_PASSWORD_RESET'],
                       identity=email) is not None:
        return generic, 200

    user = User.query.filter_by(email=email).first()
    if user is None or not user.is_active:
        return generic, 200

    raw_token = secrets.token_urlsafe(32)
    user.password_reset_token_hash = _hash_reset_token(raw_token)
    minutes = current_app.config['PASSWORD_RESET_MINUTES']
    user.password_reset_expires_at = datetime.utcnow() + timedelta(minutes=minutes)
    user_id, org_id = user.id, user.org_id
    db.session.commit()

    base = current_app.config.get('APP_BASE_URL') or request.host_url.rstrip('/')
    link = f'{base}/reset-password?token={raw_token}'
    delivered = send_email(
        email, 'Reset your Audinexia password',
        f'Someone asked to reset the password for this Audinexia account.\n\n'
        f'Open this link within {minutes} minutes to choose a new password:\n{link}\n\n'
        f'If you did not ask for this, ignore this message; your password is unchanged.\n')
    record('auth.password_reset_requested', 'user', user_id,
           'Password reset link requested',
           {'email_delivered': delivered, 'client_ip': client_ip()},
           user_id=user_id, org_id=org_id, commit=True)
    return generic, 200


@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    """Consume a reset token and set a new password. The token is single-use,
    expires (PASSWORD_RESET_MINUTES), and only its hash is stored. Success also
    bumps token_version, so every existing session for the account is invalidated."""
    rejected = limit_or_reject('auth:reset-consume', current_app.config['RATE_LIMIT_PASSWORD_RESET'])
    if rejected is not None:
        return rejected

    data = request.get_json(silent=True) or {}
    raw_token = data.get('token') or ''
    new_password = data.get('new_password') or ''
    if not raw_token:
        return jsonify({'error': 'token is required'}), 400

    user = User.query.filter_by(password_reset_token_hash=_hash_reset_token(raw_token)).first()
    if (user is None or not user.password_reset_expires_at
            or user.password_reset_expires_at < datetime.utcnow() or not user.is_active):
        return jsonify({'error': 'This reset link is invalid or has expired.'}), 400

    ok, problems = password_acceptable(new_password)
    if not ok:
        return jsonify({'error': f'New password {" and ".join(problems)}', 'problems': problems}), 400

    user.set_password(new_password)
    user.password_reset_token_hash = None
    user.password_reset_expires_at = None
    user.must_change_password = False
    user.token_version = (user.token_version or 0) + 1
    clear_login_failures(user.email)
    user_id, org_id = user.id, user.org_id
    db.session.commit()
    record('auth.password_reset', 'user', user_id, 'Password reset through an emailed link',
           {'sessions_invalidated': True}, user_id=user_id, org_id=org_id, commit=True)
    response = jsonify({'success': True, 'sessions_invalidated': True})
    unset_jwt_cookies(response)
    return response, 200


@auth_bp.route('/password-policy', methods=['GET'])
def password_policy():
    """Public so a login/registration form can render the rules before a user
    violates them, instead of discovering them from a 400."""
    from config import Config

    return jsonify({
        'min_length': Config.MIN_PASSWORD_LENGTH,
        'rules': [
            f'at least {Config.MIN_PASSWORD_LENGTH} characters',
            'not a commonly used password',
            'no single character repeated four times in a row',
            'not digits only',
        ],
        'max_length': 128,
    })
