from datetime import datetime

from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt

from extensions import db
from models import ControlResult, Risk, RiskControlLink, RISK_STATUSES, User, bucket_risk_score
from rbac import current_org_id, current_user_id, roles_required
from scanning import FRAMEWORKS

risk_bp = Blueprint('risk', __name__)

ALL_ROLES = ('org_admin', 'compliance_manager', 'auditor', 'member', 'read_only')
RISK_MANAGE_ROLES = ('org_admin', 'compliance_manager', 'auditor')

# Fields a risk's assigned owner (role == 'member' specifically -- see
# rationale in update_risk()) may update on their own risk. Everything else
# requires a RISK_MANAGE_ROLES caller.
OWNER_EDITABLE_FIELDS = ('status', 'mitigation')


def _get_org_risk(risk_id):
    """Org-scoped Risk lookup, baked directly into the query per the house
    rule -- returns None (caller returns 404) rather than fetch-then-check."""
    return Risk.query.filter_by(id=risk_id, org_id=current_org_id()).first()


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
    query = Risk.query.filter_by(org_id=org_id)

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
        if data['status'] not in RISK_STATUSES:
            return jsonify({'error': f'status must be one of: {", ".join(RISK_STATUSES)}'}), 400
        risk.status = data['status']

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
    return jsonify(risk.to_dict())


@risk_bp.route('/risks/<int:risk_id>', methods=['DELETE'])
@roles_required(*RISK_MANAGE_ROLES)
def delete_risk(risk_id):
    risk = _get_org_risk(risk_id)
    if not risk:
        return jsonify({'error': 'Not found'}), 404
    db.session.delete(risk)
    db.session.commit()
    return jsonify({'success': True})


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
