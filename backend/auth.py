from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    current_user,
    jwt_required,
)

from extensions import db, jwt, limiter
from models import Organization, User
from security import (
    check_password_pwned,
    generate_reset_token,
    hash_reset_token,
    validate_password_strength,
)

auth_bp = Blueprint('auth', __name__)

FAILED_LOGIN_LOCKOUT_THRESHOLD = 10
FAILED_LOGIN_LOCKOUT_MINUTES = 15
PASSWORD_RESET_TOKEN_MINUTES = 30


@jwt.user_lookup_loader
def _load_user(_jwt_header, jwt_payload):
    """Runs on EVERY authenticated request (not just at login), so a
    revocation is enforced immediately rather than only once the token
    naturally expires. Returning None here (deactivated user, or a token
    issued under a token_version that's since been bumped by a logout/
    password-change/admin action) fails the request via
    _user_lookup_failed below, regardless of the token's own exp claim."""
    user = User.query.get(int(jwt_payload['sub']))
    if not user or not user.is_active:
        return None
    if jwt_payload.get('tv') != user.token_version:
        return None
    return user


@jwt.user_lookup_error_loader
def _user_lookup_failed(_jwt_header, _jwt_payload):
    return jsonify({'error': 'Session is no longer valid, please log in again'}), 401


def _user_claims(user):
    return {'org_id': user.org_id, 'role': user.role, 'tv': user.token_version}


def _issue_tokens(user):
    claims = _user_claims(user)
    return {
        'access_token': create_access_token(identity=str(user.id), additional_claims=claims),
        'refresh_token': create_refresh_token(identity=str(user.id), additional_claims=claims),
    }


def _login_rate_limit_key():
    email = ((request.get_json(silent=True) or {}).get('email') or '').strip().lower()
    return f'{request.remote_addr}:{email}'


@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json(silent=True) or {}
    org_name = (data.get('org_name') or '').strip()
    name = (data.get('name') or '').strip()
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    if not org_name or not name or not email or not password:
        return jsonify({'error': 'org_name, name, email, and password are all required'}), 400
    ok, error = validate_password_strength(password)
    if not ok:
        return jsonify({'error': error}), 400
    if check_password_pwned(password) is True:
        return jsonify({
            'error': 'This password has appeared in a known data breach. Please choose a different one.'
        }), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 409

    org = Organization(name=org_name)
    db.session.add(org)
    db.session.flush()  # get org.id before commit

    user = User(org_id=org.id, email=email, name=name, role='org_admin', is_active=True)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    tokens = _issue_tokens(user)
    return jsonify({
        **tokens,
        'user': user.to_dict(),
        'organization': {'id': org.id, 'name': org.name},
    }), 201


@auth_bp.route('/login', methods=['POST'])
@limiter.limit('5 per minute', key_func=_login_rate_limit_key)
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    user = User.query.filter_by(email=email).first()

    if user and user.locked_until and user.locked_until > datetime.utcnow():
        return jsonify({
            'error': 'Account temporarily locked due to repeated failed login attempts. '
                     'Try again later.'
        }), 423

    if not user or not user.is_active or not user.check_password(password):
        if user and user.is_active:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= FAILED_LOGIN_LOCKOUT_THRESHOLD:
                user.locked_until = datetime.utcnow() + timedelta(minutes=FAILED_LOGIN_LOCKOUT_MINUTES)
                user.failed_login_attempts = 0
            db.session.commit()
        return jsonify({'error': 'Invalid email or password'}), 401

    user.failed_login_attempts = 0
    user.locked_until = None
    db.session.commit()

    tokens = _issue_tokens(user)
    return jsonify({
        **tokens,
        'user': user.to_dict(),
        'organization': {'id': user.organization.id, 'name': user.organization.name},
    }), 200


@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    access_token = create_access_token(identity=str(current_user.id), additional_claims=_user_claims(current_user))
    return jsonify({'access_token': access_token}), 200


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    # Bumping token_version invalidates every outstanding access AND
    # refresh token for this user immediately (the next request from any
    # of them fails user_lookup's tv check), not just the one token used to
    # call this endpoint. Replaces the old in-memory jti blocklist, which
    # reset on every restart and never worked across multiple workers.
    current_user.token_version += 1
    db.session.commit()
    return jsonify({'success': True}), 200


@auth_bp.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    data = request.get_json(silent=True) or {}
    current_password = data.get('current_password') or ''
    new_password = data.get('new_password') or ''

    if not current_user.check_password(current_password):
        return jsonify({'error': 'Current password is incorrect'}), 401
    ok, error = validate_password_strength(new_password)
    if not ok:
        return jsonify({'error': error}), 400
    if check_password_pwned(new_password) is True:
        return jsonify({
            'error': 'This password has appeared in a known data breach. Please choose a different one.'
        }), 400

    current_user.set_password(new_password)
    current_user.must_change_password = False
    current_user.token_version += 1  # forces re-login on every other session
    db.session.commit()
    return jsonify({'success': True}), 200


@auth_bp.route('/request-password-reset', methods=['POST'])
@limiter.limit('5 per minute', key_func=_login_rate_limit_key)
def request_password_reset():
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    user = User.query.filter_by(email=email).first()

    # Always the same response whether or not the account exists -- avoids
    # leaking which emails are registered (an enumeration channel).
    generic_response = jsonify({
        'success': True,
        'message': 'If an account exists for that email, a password reset link has been generated.',
    })

    if not user or not user.is_active:
        return generic_response, 200

    raw_token, token_hash = generate_reset_token()
    user.password_reset_token_hash = token_hash
    user.password_reset_expires_at = datetime.utcnow() + timedelta(minutes=PASSWORD_RESET_TOKEN_MINUTES)
    db.session.commit()

    # No SMTP/transactional-email provider is configured in this
    # environment. Rather than fabricate a "sent" response, the reset link
    # is logged server-side -- an operator with server access can retrieve
    # it. This is stated plainly (also in SECURITY.md) as a known gap, not
    # silently passed off as real email delivery.
    reset_link = f'/reset-password?token={raw_token}'
    print(f'[password-reset] Reset link for {user.email} (expires in '
          f'{PASSWORD_RESET_TOKEN_MINUTES} min, not emailed -- no SMTP provider configured): '
          f'{reset_link}', flush=True)

    return generic_response, 200


@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json(silent=True) or {}
    raw_token = data.get('token') or ''
    new_password = data.get('new_password') or ''

    if not raw_token:
        return jsonify({'error': 'token is required'}), 400

    token_hash = hash_reset_token(raw_token)
    user = User.query.filter_by(password_reset_token_hash=token_hash).first()

    if (
        not user
        or not user.password_reset_expires_at
        or user.password_reset_expires_at < datetime.utcnow()
    ):
        return jsonify({'error': 'Invalid or expired reset token'}), 400

    ok, error = validate_password_strength(new_password)
    if not ok:
        return jsonify({'error': error}), 400
    if check_password_pwned(new_password) is True:
        return jsonify({
            'error': 'This password has appeared in a known data breach. Please choose a different one.'
        }), 400

    user.set_password(new_password)
    user.password_reset_token_hash = None
    user.password_reset_expires_at = None
    user.must_change_password = False
    user.token_version += 1  # single-use: also invalidates any live sessions
    user.failed_login_attempts = 0
    user.locked_until = None
    db.session.commit()
    return jsonify({'success': True}), 200
