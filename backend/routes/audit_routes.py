from datetime import date, datetime

from flask import Blueprint, jsonify, request
from flask_jwt_extended import current_user

from audit_log import record_audit_event
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
# else requires an AUDIT_MANAGE_ROLES caller. 'status' is deliberately NOT
# here -- segregation of duties (item 2.7) means an owner can no longer
# close their own finding directly; they submit a request_closure instead
# (see below), which a DIFFERENT manager must approve or reject.
OWNER_EDITABLE_FIELDS = ('management_response',)

FINDING_CLOSED_STATUSES = ('resolved', 'accepted_risk', 'closed')

AUDITABLE_AUDIT_FIELDS = (
    'title', 'scope_description', 'lead_auditor_id', 'status', 'start_date', 'end_date',
)
AUDITABLE_FINDING_FIELDS = (
    'description', 'severity', 'recommendation', 'management_response', 'status', 'owner_id',
    'due_date',
)


def _json_safe(value):
    return value.isoformat() if hasattr(value, 'isoformat') else value


def _snapshot(obj, fields):
    return {f: _json_safe(getattr(obj, f)) for f in fields}


def _diff(before, after):
    return {k: {'old': before[k], 'new': after[k]} for k in before if before[k] != after[k]}


def _get_org_audit(audit_id):
    """Org-scoped Audit lookup, baked directly into the query per the house
    rule -- returns None (caller returns 404) rather than fetch-then-check.
    Excludes soft-deleted rows."""
    return Audit.query.filter_by(id=audit_id, org_id=current_org_id(), deleted_at=None).first()


def _get_org_finding(audit_id, finding_id):
    """Org- and audit-scoped Finding lookup -- both audit_id and org_id are
    baked into the query directly, never fetch-then-check. Excludes
    soft-deleted rows."""
    return Finding.query.filter_by(
        id=finding_id, audit_id=audit_id, org_id=current_org_id(), deleted_at=None
    ).first()


def _reject_if_audit_closed(audit):
    """A closed audit is a finalized record -- its findings (and the audit
    itself) are locked against further changes. Returns an error response
    tuple, or None if the audit isn't closed."""
    if audit.status == 'closed':
        return jsonify({
            'error': 'This audit is closed and its findings are locked. An org_admin must '
                     'reopen the audit first (PATCH its status with a reason).'
        }), 400
    return None


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
    query = Audit.query.filter_by(org_id=org_id, deleted_at=None)

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
    db.session.flush()
    record_audit_event(org_id, current_user_id(), 'create', 'Audit', audit.id, changes={'title': title})
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
    before = _snapshot(audit, AUDITABLE_AUDIT_FIELDS)

    is_reopen = audit.status == 'closed' and data.get('status') not in (None, 'closed')
    reason = (data.get('reason') or '').strip()

    if audit.status == 'closed' and not is_reopen:
        # Any change at all (not just status) is blocked while closed --
        # closed means finalized, not "everything but status is still
        # editable."
        return jsonify({
            'error': 'This audit is closed and locked against changes. An org_admin must '
                     'reopen it first (PATCH status to a non-closed value with a reason).'
        }), 400

    if is_reopen:
        # Reopening is deliberately restricted to org_admin specifically,
        # not the whole AUDIT_MANAGE_ROLES set this route is otherwise
        # gated by -- undoing a closed/finalized audit is a bigger action
        # than the day-to-day compliance-manager/auditor work this
        # endpoint normally does.
        if current_user.role != 'org_admin':
            return jsonify({'error': 'Only an org_admin may reopen a closed audit'}), 403
        if not reason:
            return jsonify({'error': 'reason is required to reopen a closed audit'}), 400

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
            open_findings = [
                f for f in audit.findings
                if f.deleted_at is None and f.status not in FINDING_CLOSED_STATUSES
            ]
            if open_findings:
                return jsonify({
                    'error': f'Cannot close this audit: {len(open_findings)} finding(s) are still open. '
                             f'Resolve, accept the risk on, or close every finding first.',
                    'open_finding_ids': [f.id for f in open_findings],
                }), 400
            audit.closed_at = datetime.utcnow()
            audit.closed_by_id = current_user_id()
        elif new_status == 'withdrawn':
            if audit.status == 'planned':
                return jsonify({
                    'error': "An audit still in 'planned' status should be deleted, not withdrawn "
                             "-- withdrawal is for an audit that has already progressed."
                }), 400
            if not reason:
                return jsonify({'error': 'reason is required to withdraw an audit'}), 400
        elif is_reopen:
            # Reopening clears the closed stamp -- it's no longer accurate
            # once the audit is active again.
            audit.closed_at = None
            audit.closed_by_id = None

        audit.status = new_status

    changes = _diff(before, _snapshot(audit, AUDITABLE_AUDIT_FIELDS))
    if changes:
        action = 'reopen' if is_reopen else ('withdraw' if data.get('status') == 'withdrawn' else 'update')
        record_audit_event(
            current_org_id(), current_user_id(), action, 'Audit', audit.id, changes=changes,
            reason=reason or None,
        )
    db.session.commit()
    return jsonify(audit.to_dict(include_findings=True))


@audit_bp.route('/audits/<int:audit_id>', methods=['DELETE'])
@roles_required(*AUDIT_MANAGE_ROLES)
def delete_audit(audit_id):
    audit = _get_org_audit(audit_id)
    if not audit:
        return jsonify({'error': 'Not found'}), 404

    if audit.status != 'planned':
        return jsonify({
            'error': "Only an audit still in 'planned' status can be deleted. Use PATCH "
                     "status='withdrawn' (with a reason) to remove one that has progressed further."
        }), 400

    # A scan's data outlives the audit record it was filed under -- detach
    # rather than delete.
    for assessment in list(audit.assessments):
        assessment.audit_id = None

    now = datetime.utcnow()
    actor_id = current_user_id()
    org_id = current_org_id()

    # Soft-deleting the parent audit also soft-deletes its findings --
    # mirrors what the ORM cascade used to do on a hard delete, but each
    # finding gets its own audit trail entry rather than silently
    # disappearing as a side effect of the parent's deletion.
    for finding in audit.findings:
        if finding.deleted_at is None:
            finding.deleted_at = now
            finding.deleted_by_id = actor_id
            record_audit_event(
                org_id, actor_id, 'soft_delete', 'Finding', finding.id,
                reason='parent audit deleted',
            )

    audit.deleted_at = now
    audit.deleted_by_id = actor_id
    record_audit_event(org_id, actor_id, 'soft_delete', 'Audit', audit.id)
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

    record_audit_event(
        org_id, current_user_id(), 'create', 'Finding', finding.id,
        changes={'description': description, 'severity': severity},
    )
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
    err = _reject_if_audit_closed(finding.audit)
    if err:
        return err

    role = current_user.role
    data = request.get_json(silent=True) or {}
    before = _snapshot(finding, AUDITABLE_FINDING_FIELDS)

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
        # A closing status can never be set directly through this endpoint,
        # even by a manager -- including a manager who happens to own this
        # finding themselves, which would otherwise let them approve their
        # own closure. It always goes through request_closure +
        # approve_closure below, so a DIFFERENT manager signs off.
        if new_status in FINDING_CLOSED_STATUSES:
            return jsonify({
                'error': f"Cannot set status to '{new_status}' directly -- use "
                         f"POST /audits/{audit_id}/findings/{finding_id}/request-closure so a "
                         f"different manager can independently approve it."
            }), 400
        finding.closed_at = None
        finding.closed_by_id = None
        finding.status = new_status

    changes = _diff(before, _snapshot(finding, AUDITABLE_FINDING_FIELDS))
    if changes:
        record_audit_event(
            current_org_id(), current_user_id(), 'update', 'Finding', finding.id, changes=changes
        )
    db.session.commit()
    return jsonify(finding.to_dict())


@audit_bp.route('/audits/<int:audit_id>/findings/<int:finding_id>/request-closure', methods=['POST'])
@roles_required(*ALL_ROLES)
def request_closure(audit_id, finding_id):
    """The finding's owner (or a manager) proposes closing it -- the actual
    status transition only happens once a DIFFERENT manager approves via
    approve_closure below. Requires the finding to already be linked to at
    least one scanned control result: a closure claim grounded in nothing
    but the requester's own word is exactly what this workflow (and the
    evidence-link requirement specifically) exists to prevent."""
    finding = _get_org_finding(audit_id, finding_id)
    if not finding:
        return jsonify({'error': 'Not found'}), 404
    err = _reject_if_audit_closed(finding.audit)
    if err:
        return err

    role = current_user.role
    if role not in AUDIT_MANAGE_ROLES and finding.owner_id != current_user_id():
        return jsonify({'error': "Only this finding's owner or a manager may request closure"}), 403

    if finding.pending_action:
        return jsonify({'error': f'A "{finding.pending_action}" request is already pending on this finding'}), 409

    if not finding.control_links:
        return jsonify({
            'error': 'This finding has no linked control result -- link the evidence this closure '
                     'is based on before requesting closure'
        }), 400

    data = request.get_json(silent=True) or {}
    target_status = data.get('target_status')
    if target_status not in FINDING_CLOSED_STATUSES:
        return jsonify({'error': f'target_status is required and must be one of: {", ".join(FINDING_CLOSED_STATUSES)}'}), 400
    reason = (data.get('reason') or '').strip()
    if not reason:
        return jsonify({'error': 'reason is required'}), 400

    finding.pending_action = target_status  # the specific closing status being proposed
    finding.pending_reason = reason
    finding.pending_requested_by_id = current_user_id()
    finding.pending_requested_at = datetime.utcnow()

    record_audit_event(
        current_org_id(), current_user_id(), 'request_closure', 'Finding', finding.id,
        changes={'target_status': target_status}, reason=reason,
    )
    db.session.commit()
    return jsonify(finding.to_dict())


def _resolve_closure(audit_id, finding_id, decision):
    finding = _get_org_finding(audit_id, finding_id)
    if not finding:
        return jsonify({'error': 'Not found'}), 404

    if not finding.pending_action or finding.pending_action not in FINDING_CLOSED_STATUSES:
        return jsonify({'error': 'No pending closure request on this finding'}), 409

    approver_id = current_user_id()
    if approver_id == finding.owner_id or approver_id == finding.pending_requested_by_id:
        return jsonify({
            'error': 'You cannot approve or reject a closure request you own or submitted -- '
                     'a different manager must decide it'
        }), 403

    data = request.get_json(silent=True) or {}
    decision_reason = (data.get('reason') or '').strip() or None

    if decision == 'approve':
        finding.status = finding.pending_action
        finding.closed_at = datetime.utcnow()
        finding.closed_by_id = approver_id

    record_audit_event(
        finding.org_id, approver_id,
        'approve_closure' if decision == 'approve' else 'reject_closure',
        'Finding', finding.id, reason=decision_reason,
    )

    finding.pending_action = None
    finding.pending_reason = None
    finding.pending_requested_by_id = None
    finding.pending_requested_at = None

    db.session.commit()
    return jsonify(finding.to_dict())


@audit_bp.route('/audits/<int:audit_id>/findings/<int:finding_id>/approve-closure', methods=['POST'])
@roles_required(*AUDIT_MANAGE_ROLES)
def approve_closure(audit_id, finding_id):
    return _resolve_closure(audit_id, finding_id, 'approve')


@audit_bp.route('/audits/<int:audit_id>/findings/<int:finding_id>/reject-closure', methods=['POST'])
@roles_required(*AUDIT_MANAGE_ROLES)
def reject_closure(audit_id, finding_id):
    return _resolve_closure(audit_id, finding_id, 'reject')


@audit_bp.route('/audits/<int:audit_id>/findings/<int:finding_id>', methods=['DELETE'])
@roles_required(*AUDIT_MANAGE_ROLES)
def delete_finding(audit_id, finding_id):
    finding = _get_org_finding(audit_id, finding_id)
    if not finding:
        return jsonify({'error': 'Not found'}), 404
    if finding.audit.status not in ('planned', 'in_progress'):
        return jsonify({
            'error': "A finding can only be deleted while its audit is 'planned' or "
                     "'in_progress'. Once the audit has moved past that, resolve the finding "
                     "(or request closure) through its own status instead of deleting it."
        }), 400
    finding.deleted_at = datetime.utcnow()
    finding.deleted_by_id = current_user_id()
    record_audit_event(current_org_id(), current_user_id(), 'soft_delete', 'Finding', finding.id)
    db.session.commit()
    return jsonify({'success': True})


@audit_bp.route('/audits/<int:audit_id>/findings/<int:finding_id>/links', methods=['POST'])
@roles_required(*AUDIT_MANAGE_ROLES)
def link_control(audit_id, finding_id):
    org_id = current_org_id()
    finding = _get_org_finding(audit_id, finding_id)
    if not finding:
        return jsonify({'error': 'Not found'}), 404
    err = _reject_if_audit_closed(finding.audit)
    if err:
        return err

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
    err = _reject_if_audit_closed(finding.audit)
    if err:
        return err

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
    finding = Finding.query.filter_by(id=finding_id, org_id=current_org_id(), deleted_at=None).first()
    if not finding:
        return jsonify({'error': 'Not found'}), 404

    suggested_description = f"{finding.description}"
    if finding.recommendation:
        suggested_description += f" Recommendation: {finding.recommendation}"

    return jsonify({
        'suggested_description': suggested_description,
        'finding_id': finding.id,
    })
