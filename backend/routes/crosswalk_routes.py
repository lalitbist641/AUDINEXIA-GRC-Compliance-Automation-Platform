from flask import Blueprint, jsonify, request

from crosswalk import build_crosswalk
from models import Assessment
from rbac import current_org_id, roles_required
from routes.scan_routes import reconstruct_control_dict
from scanning import FRAMEWORKS

crosswalk_bp = Blueprint('crosswalk', __name__)

ALL_ROLES = ('org_admin', 'compliance_manager', 'auditor', 'member', 'read_only')

DISCLAIMER = (
    "This is a projection based on verified cross-framework control overlap, "
    "not a direct scan against the target framework(s). Statuses are inferred "
    "from this assessment's results for controls that share a verified "
    "conceptual overlap; run a direct scan against a target framework for an "
    "authoritative result."
)


@crosswalk_bp.route('/assessments/<int:assessment_id>/crosswalk', methods=['GET'])
@roles_required(*ALL_ROLES)
def get_crosswalk(assessment_id):
    org_id = current_org_id()
    assessment = Assessment.query.filter_by(id=assessment_id, org_id=org_id).first()
    if not assessment:
        return jsonify({'error': 'Not found'}), 404
    if assessment.framework not in FRAMEWORKS:
        return jsonify({'error': 'Unknown framework for this assessment'}), 400

    source_framework = assessment.framework
    framework_info = FRAMEWORKS[source_framework]
    source_controls = [reconstruct_control_dict(cr, framework_info) for cr in assessment.control_results]

    target_param = request.args.get('target')
    if target_param:
        if target_param not in FRAMEWORKS or target_param == source_framework:
            return jsonify({'error': f'Invalid target framework: {target_param}'}), 400
        target_frameworks = [target_param]
    else:
        target_frameworks = [f for f in FRAMEWORKS if f != source_framework]

    targets = [build_crosswalk(source_framework, source_controls, tf) for tf in target_frameworks]

    return jsonify({
        'assessment_id': assessment_id,
        'source_framework': source_framework,
        'source_framework_name': framework_info['name'],
        'disclaimer': DISCLAIMER,
        'targets': targets,
    })
