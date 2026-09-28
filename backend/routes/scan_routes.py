import os
import uuid
from datetime import datetime

from flask import Blueprint, current_app, jsonify, request, send_file
from werkzeug.utils import secure_filename

from config import Config
from core.audit_trail import record
from core.scan_pipeline import ScanError, scan_file
from extensions import db
from models import ROLES, Assessment, ControlResult

ALL_ROLES = ROLES  # single source: models.ROLES

from rbac import current_org_id, current_user_id, roles_required
from reports import generate_html_report, generate_pdf_report, generate_revised_policy_pdf
from scanning import (
    FRAMEWORKS,
    allowed_file,
    analyze_control,
    extract_text,
    is_valid_extracted_text,
    score_control_result,
)
from security import limit_or_reject

scan_bp = Blueprint('scan', __name__)


def _save_upload(file, org_id):
    """Save an uploaded file with an org_id + uuid prefix to avoid the
    filename-collision risk of saving by original filename alone (confirmed
    during Phase 1 planning: files from different orgs already collided in
    the flat uploads/ folder).

    The uuid4 component also makes the stored name unguessable, which matters
    because uploads are read back by path in the monitoring re-scan path."""
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
    risk_level/fix_suggestion) are recomputed via score_control_result() — the
    same function analyze_control() itself calls — so a live scan and a
    regenerated report can never drift apart.

    Shared with assessment, crosswalk, monitoring and vendor routes, which is
    why it lives here rather than inside one view function."""
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
    result['reviewer_status'] = control_result.reviewer_status
    result['remediation_status'] = control_result.remediation_status
    return result


@scan_bp.route('/scan', methods=['POST'])
@roles_required('org_admin', 'compliance_manager', 'auditor', 'member')
def scan_document():
    rejected = limit_or_reject('scan', current_app.config['RATE_LIMIT_SCAN'],
                               identity=f"user:{current_user_id()}")
    if rejected is not None:
        return rejected

    org_id = current_org_id()
    user_id = current_user_id()

    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    file = request.files['file']
    framework = request.form.get('framework', 'dpdpa')
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    if not allowed_file(file.filename):
        return jsonify({'error': f'Invalid file type. Supported: {", ".join(sorted(Config.ALLOWED_EXTENSIONS))}'}), 400
    if framework not in FRAMEWORKS:
        return jsonify({'error': f'Framework "{framework}" not supported'}), 400

    original_filename, stored_filename, filepath = _save_upload(file, org_id)
    try:
        outcome = scan_file(filepath, original_filename, framework, org_id, user_id)
    except ScanError as exc:
        return jsonify({'error': exc.message, **exc.detail}), exc.status

    assessment = outcome['assessment']
    assessment.stored_filename = stored_filename
    db.session.commit()

    record('scan.create', 'assessment', assessment.id,
           f'Scanned {original_filename} against {framework} '
           f'({outcome["overall_score"]}%)',
           {'framework': framework, 'overall_score': outcome['overall_score'],
            'compliant': outcome['compliant_count'], 'partial': outcome['partial_count'],
            'non_compliant': outcome['non_compliant_count'],
            'filename': original_filename})

    return jsonify({
        'success': True, 'assessment_id': assessment.id, 'report_id': assessment.report_id,
        'framework': framework, 'overall_score': outcome['overall_score'],
        'controls': outcome['results'],
        'compliant_count': outcome['compliant_count'],
        'partial_count': outcome['partial_count'],
        'non_compliant_count': outcome['non_compliant_count'],
        'methodology': {
            'per_control': 'raw_score = matched required phrases / total required phrases x 100',
            'overall': 'sum(weight x score/100) / sum(weight) x 100',
            'matching': 'phrase plus synonym sets; document text only, not implemented controls',
        },
    })


@scan_bp.route('/scan/sample', methods=['POST'])
@roles_required('org_admin', 'compliance_manager', 'auditor', 'member')
def scan_sample_document():
    """Score one of the repository's reference policies by name.

    Exists so the four validation samples in Section 10 of the project report
    are reachable from the product itself (and from the test suite) instead of
    only by hand-uploading through a browser. Restricted to the known
    filenames, so it is not an arbitrary file-read primitive.
    """
    data = request.get_json(silent=True) or {}
    filename = os.path.basename(data.get('filename') or '')
    framework = data.get('framework', 'dpdpa')
    policy_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'policies')
    candidate = os.path.normpath(os.path.join(policy_dir, '**', filename))
    if not os.path.isfile(candidate):
        # Try the flat layout too (samples live in subdirectories).
        matches = [os.path.join(root, f) for root, _dirs, files in os.walk(policy_dir)
                   for f in files if f == filename]
        if not matches:
            return jsonify({'error': f'Unknown sample document: {filename}',
                            'available': sorted(
                                f for root, _dirs, files in os.walk(policy_dir) for f in files
                                if f.endswith('.txt'))}), 404
        candidate = matches[0]

    try:
        outcome = scan_file(candidate, filename, framework, current_org_id(), current_user_id(),
                            source='manual')
    except ScanError as exc:
        return jsonify({'error': exc.message, **exc.detail}), exc.status

    outcome['assessment'].stored_filename = None  # a repo sample is not an upload to retain
    db.session.commit()
    record('scan.sample', 'assessment', outcome['assessment'].id,
           f'Scanned reference document {filename} ({outcome["overall_score"]}%)',
           {'filename': filename, 'framework': framework})
    return jsonify({
        'success': True,
        'assessment_id': outcome['assessment'].id,
        'report_id': outcome['assessment'].report_id,
        'framework': framework,
        'overall_score': outcome['overall_score'],
        'controls': outcome['results'],
        'compliant_count': outcome['compliant_count'],
        'partial_count': outcome['partial_count'],
        'non_compliant_count': outcome['non_compliant_count'],
    })


@scan_bp.route('/export-report', methods=['POST', 'GET', 'OPTIONS'])
@roles_required(*ALL_ROLES)
def export_report():
    """HTML report for an assessment. GET + ?assessment_id= is supported
    alongside the original POST body, so a report link can be opened or
    bookmarked directly (audit distribution) rather than only POSTed from the
    dashboard."""
    if request.method == 'OPTIONS':
        return current_app.make_default_options_response()
    try:
        assessment_id = (request.args.get('assessment_id')
                         or (request.get_json(silent=True) or {}).get('assessment_id'))
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
        record('scan.export', 'assessment', assessment.id,
               f'Exported HTML report {assessment.report_id}', {'format': 'html'})
        response = send_file(
            html_path, as_attachment=True,
            download_name=f"Audinexia_Report_{assessment.framework}.html",
        )
        response.headers['Access-Control-Expose-Headers'] = 'Content-Disposition'
        return response
    except Exception as e:
        current_app.logger.error(f"export_report error: {e}", exc_info=True)
        return jsonify({'error': 'Report generation failed; see server log for detail'}), 500


@scan_bp.route('/export-pdf', methods=['POST', 'GET', 'OPTIONS'])
@roles_required(*ALL_ROLES)
def export_pdf():
    if request.method == 'OPTIONS':
        return current_app.make_default_options_response()
    try:
        assessment_id = (request.args.get('assessment_id')
                         or (request.get_json(silent=True) or {}).get('assessment_id'))
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
        record('scan.export', 'assessment', assessment.id,
               f'Exported PDF report {assessment.report_id}', {'format': 'pdf'})
        response = send_file(
            pdf_path, as_attachment=True,
            download_name=f"Audinexia_Report_{assessment.framework}.pdf", mimetype='application/pdf',
        )
        response.headers['Access-Control-Expose-Headers'] = 'Content-Disposition'
        return response
    except Exception as e:
        current_app.logger.error(f"export_pdf error: {e}", exc_info=True)
        return jsonify({'error': 'Report generation failed; see server log for detail'}), 500


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
        return jsonify({'error': f'Unsupported file type. Allowed: {", ".join(sorted(Config.ALLOWED_EXTENSIONS))}'}), 400
    if framework not in FRAMEWORKS:
        return jsonify({'error': f'Unknown framework: {framework}'}), 400

    try:
        original_filename, _, filepath = _save_upload(file, org_id)

        policy_text = extract_text(filepath)
        if not is_valid_extracted_text(policy_text):
            # See the long comment on is_valid_extracted_text() -- the old
            # `len(text) < 10` check here did not actually catch a failed
            # extraction, since the sentinel error strings extract_text()
            # returns on failure are themselves far longer than 10 characters.
            return jsonify({
                'error': 'Could not extract readable text from this file. It may be image-only '
                        '(scanned, no text layer), password-protected, or corrupted.',
                'extraction_detail': policy_text,
            }), 400

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
            record('scan.revise_pdf', 'assessment', None,
                   f'Generated remediation draft PDF for {original_filename} ({framework})',
                   {'gaps_found': len(missing_sections), 'format': 'pdf'})
            response = send_file(
                pdf_path, as_attachment=True,
                download_name=f"Revised_Policy_{framework}.pdf", mimetype='application/pdf',
            )
            response.headers['Access-Control-Expose-Headers'] = 'Content-Disposition'
            return response

        record('scan.revise', 'assessment', None,
               f'Generated remediation draft for {original_filename} ({framework})',
               {'gaps_found': len(missing_sections)})
        return jsonify({
            'success': True,
            'gaps_found': len(missing_sections),
            'missing_sections': missing_sections,
            'filename': f"revised_{original_filename}",
            'note': (
                'Suggested language is generated from each control\'s remediation template. It is a '
                'drafting starting point for a policy author, not text that has been reviewed for '
                'this organization\'s actual processing activities.'
            ),
        })

    except Exception as e:
        current_app.logger.error(f"revise_policy error: {e}", exc_info=True)
        return jsonify({'error': 'Remediation draft generation failed; see server log for detail'}), 500
