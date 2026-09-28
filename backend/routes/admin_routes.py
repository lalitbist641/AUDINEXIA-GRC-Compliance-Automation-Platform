from flask import Blueprint, jsonify, request

from audit_log import record_audit_event
from extensions import db
from models import ROLES, User
from rbac import current_org_id, current_user_id, roles_required
from security import validate_password_strength

admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/users', methods=['POST'])
@roles_required('org_admin')
def create_teammate():
    """Org admin creates a teammate account directly (email + temp password).
    No email-invite flow this phase (deliberate scope cut, avoids an SMTP
    dependency)."""
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    name = (data.get('name') or '').strip()
    temp_password = data.get('temp_password') or ''
    role = data.get('role', 'member')

    if not email or not name or not temp_password:
        return jsonify({'error': 'email, name, and temp_password are all required'}), 400
    ok, error = validate_password_strength(temp_password)
    if not ok:
        return jsonify({'error': error}), 400
    if role not in ROLES:
        return jsonify({'error': f'Invalid role. Must be one of: {", ".join(ROLES)}'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 409

    # org_id always comes from the calling admin's JWT claim, never the
    # request body — prevents a crafted request creating a user in a
    # different org.
    new_user = User(
        org_id=current_org_id(), email=email, name=name, role=role, is_active=True,
        must_change_password=True,
    )
    new_user.set_password(temp_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'success': True, 'user': new_user.to_dict()}), 201


@admin_bp.route('/users', methods=['GET'])
@roles_required('org_admin', 'compliance_manager', 'auditor')
def list_teammates():
    # Wider than the POST above (org_admin only, unchanged) -- compliance
    # managers and auditors need this list to populate the remediation
    # assignee dropdown. Only non-sensitive fields are returned (User.to_dict()
    # has no password_hash), so widening read access here is low-risk.
    org_id = current_org_id()
    users = User.query.filter_by(org_id=org_id).order_by(User.created_at.asc()).all()
    return jsonify({'users': [u.to_dict() for u in users]})


@admin_bp.route('/users/<int:user_id>', methods=['PATCH'])
@roles_required('org_admin')
def update_teammate(user_id):
    """Org admin changes a teammate's role or active status. Bumps the
    target's token_version so any session they already have open is
    invalidated on its very next request -- e.g. deactivating a user (or
    demoting them out of a role) takes effect immediately, not once their
    current access token happens to expire."""
    org_id = current_org_id()
    user = User.query.filter_by(id=user_id, org_id=org_id).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json(silent=True) or {}
    if 'role' not in data and 'is_active' not in data:
        return jsonify({'error': 'Provide at least one of: role, is_active'}), 400

    if user.id == current_user_id() and (
        data.get('is_active') is False or ('role' in data and data.get('role') != user.role)
    ):
        return jsonify({'error': "You cannot change your own role or deactivate your own account"}), 400

    changes = {}

    if 'role' in data:
        new_role = data['role']
        if new_role not in ROLES:
            return jsonify({'error': f'Invalid role. Must be one of: {", ".join(ROLES)}'}), 400
        if new_role != user.role:
            changes['role'] = {'old': user.role, 'new': new_role}
            user.role = new_role

    if 'is_active' in data:
        new_active = bool(data['is_active'])
        if new_active != user.is_active:
            changes['is_active'] = {'old': user.is_active, 'new': new_active}
            user.is_active = new_active

    if changes:
        user.token_version += 1
        record_audit_event(org_id, current_user_id(), 'update', 'User', user.id, changes=changes)
        db.session.commit()

    return jsonify({'success': True, 'user': user.to_dict()}), 200
