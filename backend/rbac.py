from functools import wraps

from flask import jsonify
from flask_jwt_extended import get_jwt, get_jwt_identity, jwt_required

from models import ROLES

__all__ = ['ROLES', 'roles_required', 'current_org_id', 'current_user_id']


def roles_required(*allowed_roles):
    """Require a valid JWT AND that the caller's role is one of allowed_roles.

    Usage: @roles_required('org_admin', 'compliance_manager')
    """
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            role = get_jwt().get('role')
            if role not in allowed_roles:
                return jsonify({'error': 'Forbidden: insufficient role'}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def current_org_id():
    """Caller's org_id from JWT claims. Every query touching Assessment,
    ControlResult, or User MUST filter by this value — a missed filter is a
    direct cross-tenant data leak. This is the single most important rule
    in the whole codebase."""
    return get_jwt().get('org_id')


def current_user_id():
    return int(get_jwt_identity())
