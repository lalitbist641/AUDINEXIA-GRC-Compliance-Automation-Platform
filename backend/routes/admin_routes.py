from flask import Blueprint, jsonify, request
from sqlalchemy import func

from config import Config
from core.audit_trail import record
from extensions import db
from models import (
    ROLES,
    ROLES,
    Assessment,
    Audit,
    AuditTrailEvent,
    ControlResult,
    Finding,
    Organization,
    PolicyWatch,
    Risk,
    User,
    Vendor,
)
from rbac import current_org_id, current_role, current_user_id, roles_required
from security import check_password_strength, clear_login_failures

admin_bp = Blueprint('admin', __name__)

ALL_ROLES = ROLES  # single source: models.ROLES, never a re-typed literal
MANAGE_ROLES = ('org_admin', 'compliance_manager')


@admin_bp.route('/users', methods=['POST'])
@roles_required('org_admin')
def create_teammate():
    """Org admin creates a teammate account directly with a temp password.

    There is still no email-invite flow (deliberate scope cut — it would add an
    SMTP dependency for no compliance value). The temp password forces a change
    at first login, which is what makes the "admin knows my password" window
    acceptable.
    """
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    name = (data.get('name') or '').strip()
    temp_password = data.get('temp_password') or ''
    role = data.get('role', 'member')

    if not email or not name or not temp_password:
        return jsonify({'error': 'email, name, and temp_password are all required'}), 400
    if role not in ROLES:
        return jsonify({'error': f'Invalid role. Must be one of: {", ".join(ROLES)}'}), 400
    ok, problems = check_password_strength(temp_password)
    if not ok:
        return jsonify({'error': f'temp_password {" and ".join(problems)}', 'problems': problems}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 409

    # org_id always comes from the calling admin's JWT claim, never the
    # request body — prevents a crafted request creating a user in a
    # different org.
    new_user = User(org_id=current_org_id(), email=email, name=name, role=role, is_active=True,
                    must_change_password=True)
    new_user.set_password(temp_password)
    db.session.add(new_user)
    db.session.flush()
    new_id = new_user.id
    db.session.commit()
    record('admin.user_create', 'user', new_id, f'Created {role} account for {email}',
           {'email': email, 'role': role})
    return jsonify({'success': True, 'user': new_user.to_dict(),
                    'note': 'The user must change this password at first login.'}), 201


@admin_bp.route('/users', methods=['GET'])
@roles_required('org_admin', 'compliance_manager', 'auditor')
def list_teammates():
    # Wider than the POST above (org_admin only, unchanged) -- compliance
    # managers and auditors need this list to populate the remediation
    # assignee dropdown. Only non-sensitive fields are returned (User.to_dict()
    # has no password_hash), so widening read access here is low-risk.
    org_id = current_org_id()
    users = User.query.filter_by(org_id=org_id).order_by(User.created_at.asc()).all()
    # Assignment load, so a manager distributing remediation work can see who is
    # already carrying open items. Computed here rather than in the client to
    # keep it one query per page.
    open_items = dict(
        db.session.query(ControlResult.assigned_to_id, func.count(ControlResult.id))
        .filter(ControlResult.org_id == org_id)
        .filter(ControlResult.assigned_to_id.isnot(None))
        .filter(ControlResult.remediation_status.in_(('open', 'in_progress')))
        .group_by(ControlResult.assigned_to_id)
        .all()
    )
    payload = []
    for user in users:
        item = user.to_dict()
        item['open_remediations'] = open_items.get(user.id, 0)
        payload.append(item)
    return jsonify({'users': payload, 'roles': list(ROLES)})


@admin_bp.route('/users/<int:user_id>', methods=['PATCH'])
@roles_required('org_admin')
def update_teammate(user_id):
    """Change a teammate's role or activate/deactivate them.

    Deactivation is the control that actually stops access: it bumps
    token_version, so already-issued tokens stop working at the next request
    instead of living out their 30 minutes."""
    target = User.query.filter_by(id=user_id, org_id=current_org_id()).first()
    if not target:
        return jsonify({'error': 'Not found'}), 404
    data = request.get_json(silent=True) or {}
    changes = {}

    if 'role' in data:
        if data['role'] not in ROLES:
            return jsonify({'error': f'role must be one of: {", ".join(ROLES)}'}), 400
        if target.id == current_user_id() and data['role'] != 'org_admin':
            return jsonify({'error': 'You cannot demote your own account'}), 400
        if target.role == 'org_admin' and data['role'] != 'org_admin':
            remaining_admins = User.query.filter_by(org_id=target.org_id, role='org_admin').count()
            if remaining_admins <= 1:
                return jsonify({'error': 'This is the last org_admin; promote another user first '
                                         'rather than locking the organization out of administration'}), 409
        changes['role'] = data['role']
        target.role = data['role']
        # Re-issued tokens carry the new role; existing ones must not keep
        # carrying elevated claims after a demotion.
        target.token_version = (target.token_version or 0) + 1

    if 'is_active' in data:
        is_active = bool(data['is_active'])
        if not is_active and target.id == current_user_id():
            return jsonify({'error': 'You cannot deactivate your own account'}), 400
        if not is_active and target.role == 'org_admin':
            remaining_admins = (User.query.filter_by(org_id=target.org_id, role='org_admin',
                                                     is_active=True).count())
            if remaining_admins <= 1:
                return jsonify({'error': 'This is the only active org_admin; activate another admin '
                                         'first rather than locking the organization out'}), 409
        target.is_active = is_active
        changes['is_active'] = is_active
        if not is_active:
            target.token_version = (target.token_version or 0) + 1
            clear_login_failures(target.email)
        else:
            target.token_version = (target.token_version or 0) + 1

    if 'name' in data and (data['name'] or '').strip():
        target.name = data['name'].strip()
        changes['name'] = target.name
    if 'must_change_password' in data:
        target.must_change_password = bool(data['must_change_password'])
        changes['must_change_password'] = target.must_change_password

    db.session.commit()
    record('admin.user_update', 'user', target.id,
           f'Updated user {target.email}: {", ".join(sorted(changes)) or "no-op"}', changes)
    return jsonify({'success': True, 'user': target.to_dict()})


@admin_bp.route('/users/<int:user_id>/password', methods=['POST'])
@roles_required('org_admin')
def reset_teammate_password(user_id):
    data = request.get_json(silent=True) or {}
    target = User.query.filter_by(id=user_id, org_id=current_org_id()).first()
    if not target:
        return jsonify({'error': 'Not found'}), 404
    new_password = data.get('new_password') or ''
    ok, problems = check_password_strength(new_password)
    if not ok:
        return jsonify({'error': f'new_password {" and ".join(problems)}', 'problems': problems}), 400
    target.set_password(new_password)
    target.must_change_password = True
    target.token_version = (target.token_version or 0) + 1
    clear_login_failures(target.email)
    db.session.commit()
    record('admin.password_reset', 'user', target.id, f'Reset password for {target.email}',
           {'email': target.email})
    return jsonify({'success': True, 'sessions_invalidated': True})


@admin_bp.route('/settings', methods=['GET'])
@roles_required(*ALL_ROLES)
def get_settings():
    org = db.session.get(Organization, current_org_id())
    return jsonify({
        'organization': {'id': org.id, 'name': org.name, 'created_at': org.created_at.isoformat()},
        'default_policy_review_interval_days': org.default_policy_review_interval_days
        or Config.DEFAULT_POLICY_REVIEW_INTERVAL_DAYS,
        'default_vendor_review_interval_days': org.default_vendor_review_interval_days
        or Config.DEFAULT_VENDOR_REVIEW_INTERVAL_DAYS,
        'frameworks': list(__import__('scanning').FRAMEWORKS.keys()),
        'role': current_role(),
    })


@admin_bp.route('/settings', methods=['PATCH'])
@roles_required('org_admin')
def update_settings():
    org = db.session.get(Organization, current_org_id())
    data = request.get_json(silent=True) or {}
    changes = {}
    for field, label in (('default_policy_review_interval_days', 'Policy review interval'),
                         ('default_vendor_review_interval_days', 'Vendor review interval')):
        if field in data:
            try:
                value = int(data[field])
            except (TypeError, ValueError):
                return jsonify({'error': f'{field} must be a whole number of days'}), 400
            if not 1 <= value <= 3650:
                return jsonify({'error': f'{field} must be between 1 and 3650'}), 400
            setattr(org, field, value)
            changes[field] = value
    if 'name' in data and (data['name'] or '').strip():
        org.name = data['name'].strip()[:200]
        changes['name'] = org.name
    db.session.commit()
    record('admin.settings_update', 'organization', org.id, 'Updated organization settings', changes)
    return jsonify({'success': True, 'changed': changes})


@admin_bp.route('/dashboard', methods=['GET'])
@roles_required(*ALL_ROLES)
def dashboard_rollup():
    """One call for the landing page's tiles, so the dashboard does not fan out
    to eight endpoints on load. Every number is a count over org-scoped rows."""
    org_id = current_org_id()
    from datetime import datetime

    from models import MaturityAssessment

    now = datetime.utcnow()
    latest = (Assessment.query.filter_by(org_id=org_id, vendor_id=None)
              .order_by(Assessment.created_at.desc()).limit(10).all())
    open_remediations = ControlResult.query.filter_by(org_id=org_id).filter(
        ControlResult.remediation_status.in_(('open', 'in_progress'))).count()
    overdue_remediations = ControlResult.query.filter_by(org_id=org_id).filter(
        ControlResult.remediation_status.in_(('open', 'in_progress')),
        ControlResult.due_date < now.date()).count()
    unreviewed_gaps = ControlResult.query.filter_by(org_id=org_id, reviewer_status='unreviewed').filter(
        ControlResult.status.in_(('Non-Compliant', 'Partially Compliant'))).count()

    return jsonify({
        'assessments_total': Assessment.query.filter_by(org_id=org_id).count(),
        'latest_assessments': [a.to_summary_dict() for a in latest],
        'open_risks': Risk.query.filter_by(org_id=org_id).filter(
            Risk.status.in_(('open', 'mitigating'))).count(),
        'critical_risks': Risk.query.filter_by(org_id=org_id, risk_level='Critical').filter(
            Risk.status != 'closed').count(),
        'open_findings': Finding.query.filter_by(org_id=org_id).filter(
            Finding.status.notin_(('resolved', 'closed', 'accepted_risk'))).count(),
        'audits_in_progress': Audit.query.filter_by(org_id=org_id, status='in_progress').count(),
        'vendors_total': Vendor.query.filter_by(org_id=org_id).count(),
        'vendors_unassessed': Vendor.query.filter_by(org_id=org_id, risk_tier='unassessed').count(),
        'open_remediations': open_remediations,
        'overdue_remediations': overdue_remediations,
        'unreviewed_gaps': unreviewed_gaps,
        'watches_overdue': PolicyWatch.query.filter_by(org_id=org_id, is_active=True).filter(
            PolicyWatch.next_due_at <= now).count(),
        'maturity_average': round(db.session.query(func.avg(MaturityAssessment.derived_level)).filter(
            MaturityAssessment.org_id == org_id).scalar() or 0, 2),
        'generated_at': now.isoformat(),
    })


@admin_bp.route('/audit-trail', methods=['GET'])
@roles_required('org_admin', 'compliance_manager', 'auditor')
def audit_trail():
    """Read the compliance audit trail. Auditors get read access by design —
    the trail is what an external assessor asks for first.

    Deliberately no update/delete route for this table, in any role."""
    org_id = current_org_id()
    query = AuditTrailEvent.query.filter_by(org_id=org_id)

    for field in ('entity_type', 'action'):
        value = request.args.get(field)
        if value:
            query = query.filter(getattr(AuditTrailEvent, field) == value)
    for field in ('entity_id', 'user_id'):
        value = request.args.get(field)
        if value:
            try:
                query = query.filter(getattr(AuditTrailEvent, field) == int(value))
            except ValueError:
                return jsonify({'error': f'{field} must be an integer'}), 400
    if request.args.get('since'):
        from datetime import datetime

        try:
            query = query.filter(AuditTrailEvent.created_at >= datetime.strptime(
                request.args['since'][:10], '%Y-%m-%d'))
        except ValueError:
            return jsonify({'error': 'since must be YYYY-MM-DD'}), 400

    try:
        limit = min(int(request.args.get('limit', 100)), 500)
    except ValueError:
        limit = 100
    events = query.order_by(AuditTrailEvent.created_at.desc()).limit(limit).all()
    return jsonify({
        'events': [e.to_dict() for e in events],
        'count': len(events),
        'immutable': True,
        'note': 'Append-only. There is no API path to edit or remove these rows, in any role.',
    })


@admin_bp.route('/audit-trail/stats', methods=['GET'])
@roles_required('org_admin', 'compliance_manager', 'auditor')
def audit_trail_stats():
    org_id = current_org_id()
    by_action = dict(
        db.session.query(AuditTrailEvent.action, func.count(AuditTrailEvent.id))
        .filter(AuditTrailEvent.org_id == org_id)
        .group_by(AuditTrailEvent.action)
        .order_by(func.count(AuditTrailEvent.id).desc())
        .limit(15).all()
    )
    return jsonify({
        'total': AuditTrailEvent.query.filter_by(org_id=org_id).count(),
        'by_action': by_action,
        'retention_days': Config.AUDIT_TRAIL_RETENTION_DAYS or 'unlimited',
    })
