from functools import wraps

from flask import jsonify
from flask_jwt_extended import current_user, jwt_required

from models import ROLES

__all__ = ['ROLES', 'roles_required', 'current_org_id', 'current_user_id']


def roles_required(*allowed_roles):
    """Require a valid JWT AND that the caller's role is one of allowed_roles.

    Reads role from `current_user` (the DB row loaded fresh by auth.py's
    user_lookup_loader on this request), not from the JWT's own claims --
    a claim baked in at login time would still say the caller's OLD role
    after an admin changes it, until that token naturally expires.

    Usage: @roles_required('org_admin', 'compliance_manager')
    """
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            if current_user.role not in allowed_roles:
                return jsonify({'error': 'Forbidden: insufficient role'}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def current_org_id():
    """Caller's org_id, read from the DB (current_user), not from JWT
    claims. Every query touching Assessment, ControlResult, or User MUST
    filter by this value — a missed filter is a direct cross-tenant data
    leak. This is the single most important rule in the whole codebase."""
    return current_user.org_id


def current_user_id():
    return current_user.id
