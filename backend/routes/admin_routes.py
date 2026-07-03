from flask import Blueprint, jsonify, request

from extensions import db
from models import ROLES, User
from rbac import current_org_id, roles_required

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
    if len(temp_password) < 8:
        return jsonify({'error': 'temp_password must be at least 8 characters'}), 400
    if role not in ROLES:
        return jsonify({'error': f'Invalid role. Must be one of: {", ".join(ROLES)}'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 409

    # org_id always comes from the calling admin's JWT claim, never the
    # request body — prevents a crafted request creating a user in a
    # different org.
    new_user = User(org_id=current_org_id(), email=email, name=name, role=role, is_active=True)
    new_user.set_password(temp_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'success': True, 'user': new_user.to_dict()}), 201


@admin_bp.route('/users', methods=['GET'])
@roles_required('org_admin')
def list_teammates():
    org_id = current_org_id()
    users = User.query.filter_by(org_id=org_id).order_by(User.created_at.asc()).all()
    return jsonify({'users': [u.to_dict() for u in users]})
