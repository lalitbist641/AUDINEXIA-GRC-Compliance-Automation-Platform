from flask import Blueprint, jsonify

from models import Assessment
from rbac import current_org_id, roles_required
from routes.scan_routes import reconstruct_control_dict
from scanning import FRAMEWORKS

assessment_bp = Blueprint('assessment', __name__)

ALL_ROLES = ('org_admin', 'compliance_manager', 'auditor', 'member', 'read_only')


@assessment_bp.route('/assessments', methods=['GET'])
@roles_required(*ALL_ROLES)
def list_assessments():
    org_id = current_org_id()
    rows = Assessment.query.filter_by(org_id=org_id).order_by(Assessment.created_at.desc()).all()
    return jsonify({'assessments': [a.to_summary_dict() for a in rows]})


@assessment_bp.route('/assessments/<int:assessment_id>', methods=['GET'])
@roles_required(*ALL_ROLES)
def get_assessment(assessment_id):
    org_id = current_org_id()
    # 404 (not 403) on a cross-org id — a 403 would confirm the id exists in
    # another org, a small but avoidable information leak.
    assessment = Assessment.query.filter_by(id=assessment_id, org_id=org_id).first()
    if not assessment:
        return jsonify({'error': 'Not found'}), 404

    framework_info = FRAMEWORKS.get(assessment.framework, {'controls': []})
    controls = [reconstruct_control_dict(cr, framework_info) for cr in assessment.control_results]

    summary = assessment.to_summary_dict()
    summary['controls'] = controls
    return jsonify(summary)
