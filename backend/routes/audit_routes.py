from datetime import date, datetime

from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt

from extensions import db
from models import (
    Audit,
    AUDIT_STATUSES,
    ControlResult,
    Finding,
    FINDING_SEVERITIES,
    FINDING_STATUSES,
    FindingControlLink,
    User,
)
from rbac import current_org_id, current_user_id, roles_required
from scanning import FRAMEWORKS

audit_bp = Blueprint('audit', __name__)

ALL_ROLES = ('org_admin', 'compliance_manager', 'auditor', 'member', 'read_only')
AUDIT_MANAGE_ROLES = ('org_admin', 'compliance_manager', 'auditor')

# Fields a finding's assigned owner (role == 'member' specifically -- see
# rationale in update_finding()) may update on their own finding. Everything
# else requires an AUDIT_MANAGE_ROLES caller.
OWNER_EDITABLE_FIELDS = ('status', 'management_response')

FINDING_CLOSED_STATUSES = ('resolved', 'accepted_risk', 'closed')


def _get_org_audit(audit_id):
    """Org-scoped Audit lookup, baked directly into the query per the house
    rule -- returns None (caller returns 404) rather than fetch-then-check."""
    return Audit.query.filter_by(id=audit_id, org_id=current_org_id()).first()


def _get_org_finding(audit_id, finding_id):
    """Org- and audit-scoped Finding lookup -- both audit_id and org_id are
    baked into the query directly, never fetch-then-check."""
    return Finding.query.filter_by(id=finding_id, audit_id=audit_id, org_id=current_org_id()).first()


def _parse_date(raw, field_name):
    """Returns (date_or_None, error_response_or_None)."""
    if raw is None:
        return None, None
    try:
        return datetime.strptime(raw, '%Y-%m-%d').date(), None
    except ValueError:
        return None, (jsonify({'error': f'{field_name} must be in YYYY-MM-DD format'}), 400)


# ---------------------------------------------------------------- Audits ---

@audit_bp.route('/audits', methods=['GET'])
@roles_required(*ALL_ROLES)
def list_audits():
    org_id = current_org_id()
    query = Audit.query.filter_by(org_id=org_id)

    status = request.args.get('status')
    if status:
        query = query.filter(Audit.status == status)

    rows = query.order_by(Audit.created_at.desc()).all()
    # include_findings=true lets the control-detail modal's Findings section
    # do a single fetch-all-then-filter-client-side lookup (mirroring how
    # the Risks section does the same over GET /api/risks) instead of an
    # N+1 fetch per audit. Defaults to false so the main audit list page's
    # payload stays small.
    include_findings = request.args.get('include_findings', '').lower() == 'true'
    return jsonify({'audits': [a.to_dict(include_findings=include_findings) for a in rows]})


@audit_bp.route('/audits', methods=['POST'])
@roles_required(*AUDIT_MANAGE_ROLES)
def create_audit():
    org_id = current_org_id()
    data = request.get_json(silent=True) or {}

    title = (data.get('title') or '').strip()
    if not title:
        return jsonify({'error': 'title is required'}), 400

    lead_auditor_id = data.get('lead_auditor_id')
    if lead_auditor_id is not None:
        lead = User.query.filter_by(id=lead_auditor_id, org_id=org_id).first()
        if not lead:
            return jsonify({'error': 'lead_auditor_id must be a user in your organization'}), 400

    start_date, err = _parse_date(data.get('start_date'), 'start_date')
    if err:
        return err
    end_date, err = _parse_date(data.get('end_date'), 'end_date')
    if err:
        return err

    # A new audit is always 'planned' -- status is not client-settable on
    # create, only via PATCH as the engagement actually progresses.
    audit = Audit(
        org_id=org_id, title=title, scope_description=data.get('scope_description'),
        lead_auditor_id=lead_auditor_id, status='planned',
        start_date=start_date, end_date=end_date, created_by_id=current_user_id(),
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({'success': True, 'audit': audit.to_dict(include_findings=True)}), 201


@audit_bp.route('/audits/<int:audit_id>', methods=['GET'])
@roles_required(*ALL_ROLES)
def get_audit(audit_id):
    audit = _get_org_audit(audit_id)
    if not audit:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(audit.to_dict(include_findings=True))


@audit_bp.route('/audits/<int:audit_id>', methods=['PATCH'])
@roles_required(*AUDIT_MANAGE_ROLES)
def update_audit(audit_id):
    audit = _get_org_audit(audit_id)
    if not audit:
        return jsonify({'error': 'Not found'}), 404

    data = request.get_json(silent=True) or {}

    if 'title' in data:
        title = (data['title'] or '').strip()
        if not title:
            return jsonify({'error': 'title cannot be blank'}), 400
        audit.title = title

    if 'scope_description' in data:
        audit.scope_description = data['scope_description']

    if 'lead_auditor_id' in data:
        lead_auditor_id = data['lead_auditor_id']
        if lead_auditor_id is not None:
            lead = User.query.filter_by(id=lead_auditor_id, org_id=current_org_id()).first()
            if not lead:
                return jsonify({'error': 'lead_auditor_id must be a user in your organization'}), 400
        audit.lead_auditor_id = lead_auditor_id

    if 'start_date' in data:
        start_date, err = _parse_date(data['start_date'], 'start_date')
        if err:
            return err
        audit.start_date = start_date

    if 'end_date' in data:
        end_date, err = _parse_date(data['end_date'], 'end_date')
        if err:
            return err
        audit.end_date = end_date

    if 'status' in data:
        new_status = data['status']
        if new_status not in AUDIT_STATUSES:
            return jsonify({'error': f'status must be one of: {", ".join(AUDIT_STATUSES)}'}), 400

        if new_status == 'closed':
            # An audit tool cannot claim to be closed while it still has
            # unresolved observations -- this is this phase's version of the
            # "don't let the system assert something false" rule already
            # applied elsewhere (Phase 2: remediation_status rejected on a
            # Compliant control; Phase 4: no fabricated aggregate risk score).
            open_findings = [f for f in audit.findings if f.status not in FINDING_CLOSED_STATUSES]
            if open_findings:
                return jsonify({
                    'error': f'Cannot close this audit: {len(open_findings)} finding(s) are still open. '
                             f'Resolve, accept the risk on, or close every finding first.',
                    'open_finding_ids': [f.id for f in open_findings],
                }), 400
            audit.closed_at = datetime.utcnow()
            audit.closed_by_id = current_user_id()

        audit.status = new_status

    db.session.commit()
    return jsonify(audit.to_dict(include_findings=True))


@audit_bp.route('/audits/<int:audit_id>', methods=['DELETE'])
@roles_required(*AUDIT_MANAGE_ROLES)
def delete_audit(audit_id):
    audit = _get_org_audit(audit_id)
    if not audit:
        return jsonify({'error': 'Not found'}), 404

    # A scan's data outlives the audit record it was filed under -- detach
    # rather than delete.
    for assessment in list(audit.assessments):
        assessment.audit_id = None

    db.session.delete(audit)
    db.session.commit()
    return jsonify({'success': True})


# -------------------------------------------------------------- Findings ---

@audit_bp.route('/audits/<int:audit_id>/findings', methods=['POST'])
@roles_required(*AUDIT_MANAGE_ROLES)
def create_finding(audit_id):
    org_id = current_org_id()
    audit = _get_org_audit(audit_id)
    if not audit:
        return jsonify({'error': 'Not found'}), 404
    if audit.status == 'closed':
        return jsonify({'error': 'Cannot add a finding to a closed audit'}), 400

    data = request.get_json(silent=True) or {}

    description = (data.get('description') or '').strip()
    if not description:
        return jsonify({'error': 'description is required'}), 400

    # severity is an auditor's categorical judgment call -- required,
    # never defaulted (mirrors Phase 4's likelihood/impact rule).
    severity = data.get('severity')
    if severity not in FINDING_SEVERITIES:
        return jsonify({'error': f'severity is required and must be one of: {", ".join(FINDING_SEVERITIES)}'}), 400

    owner_id = data.get('owner_id')
    if owner_id is not None:
        owner = User.query.filter_by(id=owner_id, org_id=org_id).first()
        if not owner:
            return jsonify({'error': 'owner_id must be a user in your organization'}), 400

    due_date, err = _parse_date(data.get('due_date'), 'due_date')
    if err:
        return err

    control_result_ids = data.get('control_result_ids') or []
    control_results = []
    if control_result_ids:
        bad_ids = []
        for cr_id in control_result_ids:
            cr = ControlResult.query.filter_by(id=cr_id, org_id=org_id).first()
            if not cr:
                bad_ids.append(cr_id)
            else:
                control_results.append(cr)
        if bad_ids:
            return jsonify({'error': f'control_result_ids not found in your organization: {bad_ids}'}), 400

    finding = Finding(
        org_id=org_id, audit_id=audit_id, description=description, severity=severity,
        recommendation=data.get('recommendation'), owner_id=owner_id,
        due_date=due_date, created_by_id=current_user_id(),
    )
    db.session.add(finding)
    db.session.flush()

    for cr in control_results:
        db.session.add(FindingControlLink(
            org_id=org_id, finding_id=finding.id, control_result_id=cr.id, linked_by_id=current_user_id(),
        ))
    db.session.commit()

    return jsonify({'success': True, 'finding': finding.to_dict()}), 201


@audit_bp.route('/audits/<int:audit_id>/findings/<int:finding_id>', methods=['GET'])
@roles_required(*ALL_ROLES)
def get_finding(audit_id, finding_id):
    finding = _get_org_finding(audit_id, finding_id)
    if not finding:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(finding.to_dict())


@audit_bp.route('/audits/<int:audit_id>/findings/<int:finding_id>', methods=['PATCH'])
@roles_required(*ALL_ROLES)
def update_finding(audit_id, finding_id):
    finding = _get_org_finding(audit_id, finding_id)
    if not finding:
        return jsonify({'error': 'Not found'}), 404

    role = get_jwt().get('role')
    data = request.get_json(silent=True) or {}

    is_manager = role in AUDIT_MANAGE_ROLES
    # Restricted to role == 'member' specifically, not any non-manage role --
    # a 'read_only'-named user should never gain a write path anywhere in
    # the system, even if assigned as a finding's owner for visibility.
    is_editing_owner = role == 'member' and finding.owner_id == current_user_id()

    if not is_manager and not is_editing_owner:
        return jsonify({'error': 'Forbidden: insufficient role'}), 403

    if not is_manager:
        disallowed = [k for k in data if k not in OWNER_EDITABLE_FIELDS]
        if disallowed:
            return jsonify({
                'error': f'As the assigned owner you may only update {OWNER_EDITABLE_FIELDS}; '
                         f'not allowed to change: {disallowed}. Ask an org admin, compliance '
                         f'manager, or auditor to edit these fields.'
            }), 400

    if 'description' in data:
        description = (data['description'] or '').strip()
        if not description:
            return jsonify({'error': 'description cannot be blank'}), 400
        finding.description = description

    if 'severity' in data:
        if data['severity'] not in FINDING_SEVERITIES:
            return jsonify({'error': f'severity must be one of: {", ".join(FINDING_SEVERITIES)}'}), 400
        finding.severity = data['severity']

    if 'recommendation' in data:
        finding.recommendation = data['recommendation']

    if 'management_response' in data:
        finding.management_response = data['management_response']

    if 'owner_id' in data:
        owner_id = data['owner_id']
        if owner_id is not None:
            owner = User.query.filter_by(id=owner_id, org_id=current_org_id()).first()
            if not owner:
                return jsonify({'error': 'owner_id must be a user in your organization'}), 400
        finding.owner_id = owner_id

    if 'due_date' in data:
        due_date, err = _parse_date(data['due_date'], 'due_date')
        if err:
            return err
        finding.due_date = due_date

    if 'status' in data:
        new_status = data['status']
        if new_status not in FINDING_STATUSES:
            return jsonify({'error': f'status must be one of: {", ".join(FINDING_STATUSES)}'}), 400
        if new_status in FINDING_CLOSED_STATUSES and finding.closed_at is None:
            finding.closed_at = datetime.utcnow()
            finding.closed_by_id = current_user_id()
        elif new_status not in FINDING_CLOSED_STATUSES:
            finding.closed_at = None
            finding.closed_by_id = None
        finding.status = new_status

    db.session.commit()
    return jsonify(finding.to_dict())


@audit_bp.route('/audits/<int:audit_id>/findings/<int:finding_id>', methods=['DELETE'])
@roles_required(*AUDIT_MANAGE_ROLES)
def delete_finding(audit_id, finding_id):
    finding = _get_org_finding(audit_id, finding_id)
    if not finding:
        return jsonify({'error': 'Not found'}), 404
    db.session.delete(finding)
    db.session.commit()
    return jsonify({'success': True})


@audit_bp.route('/audits/<int:audit_id>/findings/<int:finding_id>/links', methods=['POST'])
@roles_required(*AUDIT_MANAGE_ROLES)
def link_control(audit_id, finding_id):
    org_id = current_org_id()
    finding = _get_org_finding(audit_id, finding_id)
    if not finding:
        return jsonify({'error': 'Not found'}), 404

    data = request.get_json(silent=True) or {}
    control_result_id = data.get('control_result_id')
    cr = ControlResult.query.filter_by(id=control_result_id, org_id=org_id).first()
    if not cr:
        return jsonify({'error': 'control_result_id must resolve to a control result in your organization'}), 400

    existing = FindingControlLink.query.filter_by(finding_id=finding_id, control_result_id=control_result_id).first()
    if existing:
        return jsonify({'error': 'This control is already linked to this finding'}), 409

    link = FindingControlLink(
        org_id=org_id, finding_id=finding_id, control_result_id=control_result_id, linked_by_id=current_user_id(),
    )
    db.session.add(link)
    db.session.commit()
    return jsonify({'success': True, 'finding': finding.to_dict()}), 201


@audit_bp.route('/audits/<int:audit_id>/findings/<int:finding_id>/links/<int:control_result_id>', methods=['DELETE'])
@roles_required(*AUDIT_MANAGE_ROLES)
def unlink_control(audit_id, finding_id, control_result_id):
    finding = _get_org_finding(audit_id, finding_id)
    if not finding:
        return jsonify({'error': 'Not found'}), 404

    link = FindingControlLink.query.filter_by(
        finding_id=finding_id, control_result_id=control_result_id, org_id=current_org_id()
    ).first()
    if not link:
        return jsonify({'error': 'Not found'}), 404

    db.session.delete(link)
    db.session.commit()
    return jsonify({'success': True})


@audit_bp.route('/findings/<int:finding_id>/risk-suggestion', methods=['GET'])
@roles_required(*AUDIT_MANAGE_ROLES)
def risk_suggestion(finding_id):
    """Convenience pre-fill for 'create a risk from this finding'. Returns a
    suggested description ONLY -- never a likelihood/impact/risk_score key,
    mirroring risk_routes.py's control-based equivalent exactly. Those values
    remain required, explicit human input on the actual POST /api/risks call."""
    finding = Finding.query.filter_by(id=finding_id, org_id=current_org_id()).first()
    if not finding:
        return jsonify({'error': 'Not found'}), 404

    suggested_description = f"{finding.description}"
    if finding.recommendation:
        suggested_description += f" Recommendation: {finding.recommendation}"

    return jsonify({
        'suggested_description': suggested_description,
        'finding_id': finding.id,
    })
