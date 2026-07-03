from flask import Blueprint, jsonify, request
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
)

from extensions import db, jwt
from models import Organization, User

auth_bp = Blueprint('auth', __name__)

# In-memory revoked-token blocklist keyed by JWT id (jti).
# Limitation (documented, not hidden): resets on process restart and does not
# span multiple worker processes. Fine for single-process local dev; a
# DB- or Redis-backed blocklist is a Phase 2+ item for real deployment.
_revoked_tokens = set()


@jwt.token_in_blocklist_loader
def _check_if_token_revoked(jwt_header, jwt_payload):
    return jwt_payload['jti'] in _revoked_tokens


def _user_claims(user):
    return {'org_id': user.org_id, 'role': user.role}


def _issue_tokens(user):
    claims = _user_claims(user)
    return {
        'access_token': create_access_token(identity=str(user.id), additional_claims=claims),
        'refresh_token': create_refresh_token(identity=str(user.id), additional_claims=claims),
    }


@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json(silent=True) or {}
    org_name = (data.get('org_name') or '').strip()
    name = (data.get('name') or '').strip()
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    if not org_name or not name or not email or not password:
        return jsonify({'error': 'org_name, name, email, and password are all required'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
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
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    user = User.query.filter_by(email=email).first()
    if not user or not user.is_active or not user.check_password(password):
        return jsonify({'error': 'Invalid email or password'}), 401

    tokens = _issue_tokens(user)
    return jsonify({
        **tokens,
        'user': user.to_dict(),
        'organization': {'id': user.organization.id, 'name': user.organization.name},
    }), 200


@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    if not user or not user.is_active:
        return jsonify({'error': 'User not found or inactive'}), 401
    access_token = create_access_token(identity=str(user.id), additional_claims=_user_claims(user))
    return jsonify({'access_token': access_token}), 200


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    _revoked_tokens.add(jti)
    return jsonify({'success': True}), 200
