from datetime import date, datetime, timedelta

from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt

from extensions import db
from models import ControlResult, Risk, RiskControlLink, RISK_STATUSES, User, bucket_risk_score, ROLES
from rbac import current_org_id, current_user_id, roles_required
from scanning import FRAMEWORKS
from core.audit_trail import record

risk_bp = Blueprint('risk', __name__)

ALL_ROLES = ROLES  # single source: models.ROLES, never a re-typed literal
RISK_MANAGE_ROLES = ('org_admin', 'compliance_manager', 'auditor')

# Fields a risk's assigned owner (role == 'member' specifically -- see
# rationale in update_risk()) may update on their own risk. Everything else
# requires a RISK_MANAGE_ROLES caller. An owner may move status among the
# NON-terminal values (e.g. open -> mitigating) but never to a terminal one:
# segregation of duties -- an owner can't accept or close their own risk
# (OWNER_FORBIDDEN_STATUSES below). Acceptance goes through
# request_risk_acceptance, which a DIFFERENT manager must approve or reject.
OWNER_EDITABLE_FIELDS = ('status', 'mitigation')
OWNER_FORBIDDEN_STATUSES = ('accepted', 'closed')

MAX_RISK_ACCEPTANCE_MONTHS = 12


def _get_org_risk(risk_id):
    """Org-scoped Risk lookup, baked directly into the query per the house
    rule -- returns None (caller returns 404) rather than fetch-then-check.
    Excludes soft-deleted rows: a deleted risk is gone from every normal lookup,
    but the row (and its audit trail) still exists underneath."""
    return Risk.query.filter_by(id=risk_id, org_id=current_org_id(), deleted_at=None).first()


def _validate_score_component(data, key):
    """likelihood/impact must be an explicit int 1-5. Returns (value, error_response)."""
    if key not in data or data[key] is None:
        return None, (jsonify({'error': f'{key} is required (int 1-5) -- it is never defaulted'}), 400)
    value = data[key]
    if not isinstance(value, int) or isinstance(value, bool) or not (1 <= value <= 5):
        return None, (jsonify({'error': f'{key} must be an integer between 1 and 5'}), 400)
    return value, None


@risk_bp.route('/risks', methods=['GET'])
@roles_required(*ALL_ROLES)
def list_risks():
    org_id = current_org_id()
    query = Risk.query.filter_by(org_id=org_id, deleted_at=None)

    status = request.args.get('status')
    if status:
        query = query.filter(Risk.status == status)
    risk_level = request.args.get('risk_level')
    if risk_level:
        query = query.filter(Risk.risk_level == risk_level)
    owner_id = request.args.get('owner_id')
    if owner_id:
        query = query.filter(Risk.owner_id == owner_id)

    rows = query.order_by(Risk.risk_score.desc(), Risk.created_at.desc()).all()
    return jsonify({'risks': [r.to_dict() for r in rows]})


@risk_bp.route('/risks', methods=['POST'])
@roles_required(*RISK_MANAGE_ROLES)
def create_risk():
    org_id = current_org_id()
    data = request.get_json(silent=True) or {}

    description = (data.get('description') or '').strip()
    if not description:
        return jsonify({'error': 'description is required'}), 400

    likelihood, err = _validate_score_component(data, 'likelihood')
    if err:
        return err
    impact, err = _validate_score_component(data, 'impact')
    if err:
        return err

    owner_id = data.get('owner_id')
    if owner_id is not None:
        owner = User.query.filter_by(id=owner_id, org_id=org_id).first()
        if not owner:
            return jsonify({'error': 'owner_id must be a user in your organization'}), 400

    status = data.get('status', 'open')
    if status not in RISK_STATUSES:
        return jsonify({'error': f'status must be one of: {", ".join(RISK_STATUSES)}'}), 400
    if status == 'accepted':
        # A risk can't be born accepted: acceptance is a second-person decision
        # (request_risk_acceptance + approve_risk_acceptance).
        return jsonify({
            'error': "A new risk cannot be created as 'accepted' -- create it, then use "
                     "POST /api/risks/<id>/request-risk-acceptance so a different manager approves it."
        }), 400

    review_date = None
    if data.get('review_date'):
        try:
            review_date = datetime.strptime(data['review_date'], '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'error': 'review_date must be in YYYY-MM-DD format'}), 400

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

    # risk_score/risk_level are always server-computed from the human-supplied
    # likelihood/impact -- any risk_score/risk_level sent in the request body
    # is ignored, never trusted.
    risk_score = likelihood * impact
    risk = Risk(
        org_id=org_id, description=description, likelihood=likelihood, impact=impact,
        risk_score=risk_score, risk_level=bucket_risk_score(risk_score),
        owner_id=owner_id, status=status, mitigation=data.get('mitigation'),
        review_date=review_date, created_by_id=current_user_id(),
    )
    db.session.add(risk)
    db.session.flush()

    for cr in control_results:
        db.session.add(RiskControlLink(
            org_id=org_id, risk_id=risk.id, control_result_id=cr.id, linked_by_id=current_user_id(),
        ))
    db.session.commit()
    record('risk.create', 'risk', risk.id,
           f'Logged {risk.risk_level} risk (score {risk.risk_score}): '
           f'{(risk.description or "")[:90]}',
           {'likelihood': likelihood, 'impact': impact, 'status': status,
            'linked_control_results': [cr.id for cr in control_results]})

    return jsonify({'success': True, 'risk': risk.to_dict()}), 201


@risk_bp.route('/risks/<int:risk_id>', methods=['GET'])
@roles_required(*ALL_ROLES)
def get_risk(risk_id):
    risk = _get_org_risk(risk_id)
    if not risk:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(risk.to_dict())


@risk_bp.route('/risks/<int:risk_id>', methods=['PATCH'])
@roles_required(*ALL_ROLES)
def update_risk(risk_id):
    risk = _get_org_risk(risk_id)
    if not risk:
        return jsonify({'error': 'Not found'}), 404

    role = get_jwt().get('role')
    data = request.get_json(silent=True) or {}

    is_manager = role in RISK_MANAGE_ROLES
    # The owner-self-edit carve-out is deliberately restricted to role ==
    # 'member' specifically, not any non-manage role -- a 'read_only'-named
    # user should never gain a write path anywhere in the system, even if
    # assigned as a risk's owner for visibility/accountability purposes.
    is_editing_owner = role == 'member' and risk.owner_id == current_user_id()

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
        risk.description = description

    if 'likelihood' in data or 'impact' in data:
        likelihood = data.get('likelihood', risk.likelihood)
        impact = data.get('impact', risk.impact)
        for label, value in (('likelihood', likelihood), ('impact', impact)):
            if not isinstance(value, int) or isinstance(value, bool) or not (1 <= value <= 5):
                return jsonify({'error': f'{label} must be an integer between 1 and 5'}), 400
        risk.likelihood = likelihood
        risk.impact = impact
        risk.risk_score = likelihood * impact
        risk.risk_level = bucket_risk_score(risk.risk_score)

    if 'owner_id' in data:
        owner_id = data['owner_id']
        if owner_id is not None:
            owner = User.query.filter_by(id=owner_id, org_id=current_org_id()).first()
            if not owner:
                return jsonify({'error': 'owner_id must be a user in your organization'}), 400
        risk.owner_id = owner_id

    if 'status' in data:
        new_status = data['status']
        if new_status not in RISK_STATUSES:
            return jsonify({'error': f'status must be one of: {", ".join(RISK_STATUSES)}'}), 400
        if not is_manager and new_status != risk.status and new_status in OWNER_FORBIDDEN_STATUSES:
            return jsonify({
                'error': f"As the assigned owner you cannot set your own risk to '{new_status}'. "
                         f"Use POST /api/risks/<id>/request-risk-acceptance (a different manager "
                         f"approves it), or ask a manager to close it."
            }), 400
        # 'accepted' can never be set directly through this endpoint, even by a
        # manager -- including a manager who happens to own this risk, who would
        # otherwise approve their own request. It always goes through
        # request_risk_acceptance + approve_risk_acceptance, so a DIFFERENT
        # manager signs off. Only an actual transition is blocked: re-saving an
        # already-accepted risk with its unchanged status is fine.
        if new_status != risk.status:
            if new_status == 'accepted':
                return jsonify({
                    'error': "Cannot set status to 'accepted' directly -- use "
                             "POST /api/risks/<id>/request-risk-acceptance so a different "
                             "manager can independently approve it."
                }), 400
            if risk.status == 'accepted':
                risk.risk_acceptance_expires_at = None  # no longer an active acceptance
            risk.status = new_status

    if 'mitigation' in data:
        risk.mitigation = data['mitigation']

    if 'review_date' in data:
        review_date_raw = data['review_date']
        if review_date_raw is None:
            risk.review_date = None
        else:
            try:
                risk.review_date = datetime.strptime(review_date_raw, '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'review_date must be in YYYY-MM-DD format'}), 400

    if 'residual_likelihood' in data or 'residual_impact' in data:
        residual_likelihood = data.get('residual_likelihood', risk.residual_likelihood)
        residual_impact = data.get('residual_impact', risk.residual_impact)
        if (residual_likelihood is None) != (residual_impact is None):
            return jsonify({'error': 'residual_likelihood and residual_impact must be set together'}), 400
        if residual_likelihood is not None:
            for label, value in (('residual_likelihood', residual_likelihood), ('residual_impact', residual_impact)):
                if not isinstance(value, int) or isinstance(value, bool) or not (1 <= value <= 5):
                    return jsonify({'error': f'{label} must be an integer between 1 and 5'}), 400
            risk.residual_likelihood = residual_likelihood
            risk.residual_impact = residual_impact
            risk.residual_risk_score = residual_likelihood * residual_impact
            risk.residual_risk_level = bucket_risk_score(risk.residual_risk_score)
        else:
            risk.residual_likelihood = None
            risk.residual_impact = None
            risk.residual_risk_score = None
            risk.residual_risk_level = None

    db.session.commit()
    # Fields the caller sent, not fields that differ: the trail answers "what was
    # this person trying to change", and re-deriving a diff here would hide a
    # no-op write that an auditor may still want to see.
    record('risk.update', 'risk', risk.id,
           f'Updated risk {risk.id}: {", ".join(sorted(data)) or "no fields supplied"}',
           {'fields': sorted(data), 'risk_score': risk.risk_score,
            'risk_level': risk.risk_level, 'residual_risk_score': risk.residual_risk_score,
            'self_edit': not is_manager})
    return jsonify(risk.to_dict())


@risk_bp.route('/risks/<int:risk_id>', methods=['DELETE'])
@roles_required(*RISK_MANAGE_ROLES)
def delete_risk(risk_id):
    risk = _get_org_risk(risk_id)
    if not risk:
        return jsonify({'error': 'Not found'}), 404
    # Captured before the delete: after db.session.delete() the row is gone at
    # flush time, and a summary of "Deleted risk" with no description is useless
    # in a trail review.
    description = (risk.description or '')[:120]
    risk_id_value, level, score = risk.id, risk.risk_level, risk.risk_score
    # Soft delete: the row and its history survive; every normal query filters
    # deleted_at, so it disappears from the product exactly as a hard delete
    # would, without destroying the evidence trail.
    risk.deleted_at = datetime.utcnow()
    risk.deleted_by_id = current_user_id()
    db.session.commit()
    record('risk.delete', 'risk', risk_id_value,
           f'Deleted {level} risk (score {score}): {description}',
           {'soft_delete': True})
    return jsonify({'success': True})


@risk_bp.route('/risks/<int:risk_id>/request-risk-acceptance', methods=['POST'])
@roles_required(*ALL_ROLES)
def request_risk_acceptance(risk_id):
    """The risk's owner (or a manager) proposes accepting the risk as-is. The
    transition to status='accepted' only happens once a DIFFERENT manager
    approves via approve_risk_acceptance. A written justification and an expiry
    date capped at 12 months are mandatory -- an acceptance with no stated
    reason or review-by date is exactly the unaccountable risk acceptance this
    workflow exists to prevent."""
    risk = _get_org_risk(risk_id)
    if not risk:
        return jsonify({'error': 'Not found'}), 404

    role = get_jwt().get('role')
    if role not in RISK_MANAGE_ROLES and not (role == 'member' and risk.owner_id == current_user_id()):
        return jsonify({'error': "Only this risk's owner or a manager may request risk acceptance"}), 403

    if risk.pending_action:
        return jsonify({'error': f'A "{risk.pending_action}" request is already pending on this risk'}), 409

    data = request.get_json(silent=True) or {}
    reason = (data.get('reason') or '').strip()
    if not reason:
        return jsonify({'error': 'reason (written justification) is required'}), 400

    expiry_raw = data.get('expiry_date')
    if not expiry_raw:
        return jsonify({'error': 'expiry_date is required (YYYY-MM-DD)'}), 400
    try:
        expiry_date = datetime.strptime(expiry_raw, '%Y-%m-%d').date()
    except (ValueError, TypeError):
        return jsonify({'error': 'expiry_date must be in YYYY-MM-DD format'}), 400

    today = date.today()
    max_expiry = today + timedelta(days=365)
    if expiry_date <= today:
        return jsonify({'error': 'expiry_date must be in the future'}), 400
    if expiry_date > max_expiry:
        return jsonify({
            'error': f'expiry_date cannot be more than {MAX_RISK_ACCEPTANCE_MONTHS} months out '
                     f'({max_expiry.isoformat()} at the latest)'
        }), 400

    risk.pending_action = 'risk_acceptance'
    risk.pending_reason = reason
    risk.pending_expiry_date = expiry_date
    risk.pending_requested_by_id = current_user_id()
    risk.pending_requested_at = datetime.utcnow()
    db.session.commit()
    record('risk.request_acceptance', 'risk', risk.id,
           f'Requested acceptance of risk {risk.id} until {expiry_date.isoformat()}',
           {'expiry_date': expiry_date.isoformat(), 'reason': reason})
    return jsonify(risk.to_dict())


def _resolve_risk_acceptance(risk_id, decision):
    risk = _get_org_risk(risk_id)
    if not risk:
        return jsonify({'error': 'Not found'}), 404
    if risk.pending_action != 'risk_acceptance':
        return jsonify({'error': 'No pending risk-acceptance request on this risk'}), 409

    approver_id = current_user_id()
    # Neither the risk's designated owner nor whoever submitted the request may
    # decide it -- a manager who also owns this risk cannot sign off on their own
    # request. Checked against both ids, not role, so the role bypass can't help.
    if approver_id == risk.owner_id or approver_id == risk.pending_requested_by_id:
        return jsonify({
            'error': 'You cannot approve or reject a risk-acceptance request you own or submitted '
                     '-- a different manager must decide it'
        }), 403

    data = request.get_json(silent=True) or {}
    decision_reason = (data.get('reason') or '').strip() or None
    expiry = risk.pending_expiry_date

    if decision == 'approve':
        risk.status = 'accepted'
        risk.risk_acceptance_expires_at = expiry

    risk.pending_action = None
    risk.pending_reason = None
    risk.pending_expiry_date = None
    risk.pending_requested_by_id = None
    risk.pending_requested_at = None
    db.session.commit()
    record(f'risk.{decision}_acceptance', 'risk', risk.id,
           f'{"Approved" if decision == "approve" else "Rejected"} acceptance of risk {risk.id}',
           {'reason': decision_reason, 'expiry_date': expiry.isoformat() if expiry else None})
    return jsonify(risk.to_dict())


@risk_bp.route('/risks/<int:risk_id>/approve-risk-acceptance', methods=['POST'])
@roles_required(*RISK_MANAGE_ROLES)
def approve_risk_acceptance(risk_id):
    return _resolve_risk_acceptance(risk_id, 'approve')


@risk_bp.route('/risks/<int:risk_id>/reject-risk-acceptance', methods=['POST'])
@roles_required(*RISK_MANAGE_ROLES)
def reject_risk_acceptance(risk_id):
    return _resolve_risk_acceptance(risk_id, 'reject')


@risk_bp.route('/risks/<int:risk_id>/links', methods=['POST'])
@roles_required(*RISK_MANAGE_ROLES)
def link_control(risk_id):
    org_id = current_org_id()
    risk = _get_org_risk(risk_id)
    if not risk:
        return jsonify({'error': 'Not found'}), 404

    data = request.get_json(silent=True) or {}
    control_result_id = data.get('control_result_id')
    cr = ControlResult.query.filter_by(id=control_result_id, org_id=org_id).first()
    if not cr:
        return jsonify({'error': 'control_result_id must resolve to a control result in your organization'}), 400

    existing = RiskControlLink.query.filter_by(risk_id=risk_id, control_result_id=control_result_id).first()
    if existing:
        return jsonify({'error': 'This control is already linked to this risk'}), 409

    link = RiskControlLink(
        org_id=org_id, risk_id=risk_id, control_result_id=control_result_id, linked_by_id=current_user_id(),
    )
    db.session.add(link)
    db.session.commit()
    record('risk.link', 'risk', risk_id,
           f'Linked control result {control_result_id} to risk {risk_id}',
           {'control_result_id': control_result_id})
    return jsonify({'success': True, 'risk': risk.to_dict()}), 201


@risk_bp.route('/risks/<int:risk_id>/links/<int:control_result_id>', methods=['DELETE'])
@roles_required(*RISK_MANAGE_ROLES)
def unlink_control(risk_id, control_result_id):
    risk = _get_org_risk(risk_id)
    if not risk:
        return jsonify({'error': 'Not found'}), 404

    link = RiskControlLink.query.filter_by(
        risk_id=risk_id, control_result_id=control_result_id, org_id=current_org_id()
    ).first()
    if not link:
        return jsonify({'error': 'Not found'}), 404

    db.session.delete(link)
    db.session.commit()
    record('risk.unlink', 'risk', risk_id,
           f'Unlinked control result {control_result_id} from risk {risk_id}',
           {'control_result_id': control_result_id})
    return jsonify({'success': True})


@risk_bp.route('/control-results/<int:control_result_id>/risk-suggestion', methods=['GET'])
@roles_required(*RISK_MANAGE_ROLES)
def risk_suggestion(control_result_id):
    """Convenience pre-fill for 'create a risk from this control'. Returns a
    suggested description ONLY -- never a likelihood/impact/risk_score key,
    so there is nothing for the frontend to accidentally auto-fill into
    those inputs. Those values remain required, explicit human input on the
    actual POST /api/risks call."""
    cr = ControlResult.query.filter_by(id=control_result_id, org_id=current_org_id()).first()
    if not cr:
        return jsonify({'error': 'Not found'}), 404

    framework = cr.assessment.framework
    framework_info = FRAMEWORKS.get(framework, {'controls': []})
    control_def = next((c for c in framework_info['controls'] if c['id'] == cr.control_id), None)

    if control_def:
        why_matters = control_def.get('why_matters', '')
        remediation = control_def.get('remediation_example', '')
        suggested_description = f"{cr.control_name}: {why_matters} {remediation}".strip()
    else:
        suggested_description = cr.control_name

    return jsonify({
        'suggested_description': suggested_description,
        'control_result_id': cr.id,
    })
