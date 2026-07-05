import os
import uuid
from datetime import datetime

from flask import Blueprint, current_app, jsonify, request, send_file
from werkzeug.utils import secure_filename

from config import Config
from extensions import db
from models import Assessment, ControlResult
from rbac import current_org_id, current_user_id, roles_required
from reports import generate_html_report, generate_pdf_report, generate_revised_policy_pdf
from scanning import (
    FRAMEWORKS,
    allowed_file,
    analyze_control,
    calculate_weighted_score,
    extract_text,
    score_control_result,
)

scan_bp = Blueprint('scan', __name__)


def _save_upload(file, org_id):
    """Save an uploaded file with an org_id + uuid prefix to avoid the
    filename-collision risk of saving by original filename alone (confirmed
    during Phase 1 planning: files from different orgs already collided in
    the flat uploads/ folder)."""
    original_filename = secure_filename(file.filename)
    stored_filename = f"{org_id}_{uuid.uuid4().hex}_{original_filename}"
    filepath = os.path.join(Config.UPLOAD_FOLDER, stored_filename)
    file.save(filepath)
    return original_filename, stored_filename, filepath


def reconstruct_control_dict(control_result, framework_info):
    """Rebuild a full analyze_control()-shaped dict for a persisted
    ControlResult, for report regeneration from assessment_id. Static fields
    (clause/owner/severity/weight/why_matters/remediation_example) come from
    the framework's control definition; derived fields (status/symbol/
    risk_level/fix_suggestion) are recomputed via score_control_result() —
    the same function analyze_control() itself calls — so a live scan and a
    regenerated report can never drift apart."""
    control_def = next(
        (c for c in framework_info['controls'] if c['id'] == control_result.control_id), None
    )
    if control_def is None:
        # Framework definition changed since this assessment was scanned;
        # fall back to whatever is on the persisted row rather than crashing.
        control_def = {
            'id': control_result.control_id, 'name': control_result.control_name,
            'clause': '', 'owner': '', 'severity': '', 'weight': 1,
            'why_matters': '', 'remediation_example': '',
        }
    result = score_control_result(
        control_def,
        control_result.score,
        control_result.found_phrases or [],
        control_result.missing_phrases or [],
        control_result.evidence_text or '',
    )
    # control_result.id is the DB row's primary key -- distinct from result['id'],
    # which is the framework's control_id string (e.g. "DPDPA-1"). Phase 2's
    # review/evidence endpoints key on this.
    result['control_result_id'] = control_result.id
    return result


@scan_bp.route('/scan', methods=['POST'])
@roles_required('org_admin', 'compliance_manager', 'auditor', 'member')
def scan_document():
    org_id = current_org_id()
    user_id = current_user_id()

    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    file = request.files['file']
    framework = request.form.get('framework', 'dpdpa')
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    if not allowed_file(file.filename):
        return jsonify({'error': f'Invalid file type. Supported: {", ".join(Config.ALLOWED_EXTENSIONS)}'}), 400
    if framework not in FRAMEWORKS:
        return jsonify({'error': f'Framework "{framework}" not supported'}), 400

    original_filename, stored_filename, filepath = _save_upload(file, org_id)
    policy_text = extract_text(filepath)
    if not policy_text:
        policy_text = "No policy content found"

    framework_info = FRAMEWORKS[framework]
    results = [analyze_control(policy_text, ctrl) for ctrl in framework_info['controls']]
    overall_score = calculate_weighted_score(results)
    report_id = datetime.now().strftime('AUD-%Y%m%d-%H%M%S')

    compliant_count = sum(1 for r in results if r['status'] == 'Compliant')
    partial_count = sum(1 for r in results if r['status'] == 'Partially Compliant')
    non_compliant_count = sum(1 for r in results if r['status'] == 'Non-Compliant')

    assessment = Assessment(
        org_id=org_id, user_id=user_id, framework=framework,
        filename=original_filename, stored_filename=stored_filename,
        overall_score=overall_score,
        compliant_count=compliant_count, partial_count=partial_count,
        non_compliant_count=non_compliant_count, report_id=report_id,
    )
    db.session.add(assessment)
    db.session.flush()  # populate assessment.id before commit

    for r in results:
        cr = ControlResult(
            org_id=org_id, assessment_id=assessment.id, control_id=r['id'], control_name=r['name'],
            score=r['score'], status=r['status'], evidence_text=r['evidence'],
            missing_phrases=r['missing_phrases'], found_phrases=r['found_phrases'],
            remediation_status=(None if r['status'] == 'Compliant' else 'open'),
        )
        db.session.add(cr)
        db.session.flush()  # populate cr.id so it can be threaded into the response below
        r['control_result_id'] = cr.id
    db.session.commit()

    return jsonify({
        'success': True, 'assessment_id': assessment.id, 'report_id': report_id,
        'framework': framework, 'overall_score': overall_score, 'controls': results,
        'compliant_count': compliant_count,
        'partial_count': partial_count,
        'non_compliant_count': non_compliant_count,
    })


@scan_bp.route('/export-report', methods=['POST', 'OPTIONS'])
@roles_required('org_admin', 'compliance_manager', 'auditor', 'member', 'read_only')
def export_report():
    if request.method == 'OPTIONS':
        return current_app.make_default_options_response()
    try:
        data = request.get_json(silent=True) or {}
        assessment_id = data.get('assessment_id')
        if not assessment_id:
            return jsonify({'error': 'assessment_id is required'}), 400

        assessment = Assessment.query.filter_by(id=assessment_id, org_id=current_org_id()).first()
        if not assessment:
            return jsonify({'error': 'Assessment not found'}), 404
        if assessment.framework not in FRAMEWORKS:
            return jsonify({'error': 'Unknown framework for this assessment'}), 400

        framework_info = FRAMEWORKS[assessment.framework]
        results = [reconstruct_control_dict(cr, framework_info) for cr in assessment.control_results]
        html_path = generate_html_report(
            results, assessment.overall_score, assessment.filename, framework_info, assessment.report_id
        )
        response = send_file(
            html_path, as_attachment=True,
            download_name=f"Audinexia_Report_{assessment.framework}.html",
        )
        response.headers['Access-Control-Expose-Headers'] = 'Content-Disposition'
        return response
    except Exception as e:
        current_app.logger.error(f"export_report error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@scan_bp.route('/export-pdf', methods=['POST', 'OPTIONS'])
@roles_required('org_admin', 'compliance_manager', 'auditor', 'member', 'read_only')
def export_pdf():
    if request.method == 'OPTIONS':
        return current_app.make_default_options_response()
    try:
        data = request.get_json(silent=True) or {}
        assessment_id = data.get('assessment_id')
        if not assessment_id:
            return jsonify({'error': 'assessment_id is required'}), 400

        assessment = Assessment.query.filter_by(id=assessment_id, org_id=current_org_id()).first()
        if not assessment:
            return jsonify({'error': 'Assessment not found'}), 404
        if assessment.framework not in FRAMEWORKS:
            return jsonify({'error': 'Unknown framework for this assessment'}), 400

        framework_info = FRAMEWORKS[assessment.framework]
        results = [reconstruct_control_dict(cr, framework_info) for cr in assessment.control_results]
        pdf_path = generate_pdf_report(
            results, assessment.overall_score, assessment.filename, framework_info, assessment.report_id
        )
        response = send_file(
            pdf_path, as_attachment=True,
            download_name=f"Audinexia_Report_{assessment.framework}.pdf", mimetype='application/pdf',
        )
        response.headers['Access-Control-Expose-Headers'] = 'Content-Disposition'
        return response
    except Exception as e:
        current_app.logger.error(f"export_pdf error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@scan_bp.route('/revise-policy', methods=['POST', 'OPTIONS'])
@roles_required('org_admin', 'compliance_manager')
def revise_policy():
    if request.method == 'OPTIONS':
        return current_app.make_default_options_response()

    org_id = current_org_id()

    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    file = request.files['file']
    framework = request.form.get('framework', 'dpdpa')
    output_pdf = request.form.get('pdf', 'false').lower() == 'true'

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    if not allowed_file(file.filename):
        return jsonify({'error': f'Unsupported file type. Allowed: {", ".join(Config.ALLOWED_EXTENSIONS)}'}), 400
    if framework not in FRAMEWORKS:
        return jsonify({'error': f'Unknown framework: {framework}'}), 400

    try:
        original_filename, _, filepath = _save_upload(file, org_id)

        policy_text = extract_text(filepath)
        if not policy_text or len(policy_text.strip()) < 10:
            return jsonify({'error': 'Could not extract text from file'}), 400

        controls = FRAMEWORKS[framework]['controls']
        framework_info = FRAMEWORKS[framework]

        missing_sections = []
        for control in controls:
            result = analyze_control(policy_text, control)
            if result['missing_phrases']:
                missing_sections.append({
                    'control_id': control['id'],
                    'control_name': control['name'],
                    'missing': result['missing_phrases'],
                    'remediation': control['remediation_example'],
                })

        if output_pdf:
            pdf_path = generate_revised_policy_pdf(
                policy_text, missing_sections,
                framework_info['name'], original_filename, framework_info
            )
            response = send_file(
                pdf_path, as_attachment=True,
                download_name=f"Revised_Policy_{framework}.pdf", mimetype='application/pdf',
            )
            response.headers['Access-Control-Expose-Headers'] = 'Content-Disposition'
            return response

        return jsonify({
            'success': True,
            'gaps_found': len(missing_sections),
            'missing_sections': missing_sections,
            'filename': f"revised_{original_filename}",
        })

    except Exception as e:
        current_app.logger.error(f"revise_policy error: {e}", exc_info=True)
        return jsonify({'error': f'Internal error: {str(e)}'}), 500
