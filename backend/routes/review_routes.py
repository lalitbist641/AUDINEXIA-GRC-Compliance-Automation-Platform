import os
from datetime import date, datetime

from flask import Blueprint, current_app, jsonify, request, send_file

from config import Config
from extensions import db
from models import Assessment, ControlResult, EvidenceFile, REMEDIATION_STATUSES, REVIEWER_STATUSES, User
from rbac import current_org_id, current_user_id, roles_required
from routes.scan_routes import _save_upload
from scanning import FRAMEWORKS

review_bp = Blueprint('review', __name__)

ALL_ROLES = ('org_admin', 'compliance_manager', 'auditor', 'member', 'read_only')
REVIEWER_ROLES = ('org_admin', 'compliance_manager', 'auditor')
EVIDENCE_UPLOAD_ROLES = ('org_admin', 'compliance_manager', 'auditor', 'member')
EVIDENCE_DELETE_ROLES = ('org_admin', 'compliance_manager')

# Evidence covers screenshots, config exports, certificates, logs -- a
# broader set than the policy-document scan uploads (Config.ALLOWED_EXTENSIONS,
# txt/pdf/docx only). Kept separate rather than widening the scan uploader's
# allowlist, since an image is never a valid policy document to scan.
EVIDENCE_ALLOWED_EXTENSIONS = {'txt', 'pdf', 'docx', 'png', 'jpg', 'jpeg', 'csv', 'log'}


def _evidence_file_allowed(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in EVIDENCE_ALLOWED_EXTENSIONS


def _get_org_control_result(control_result_id):
    """Org-scoped ControlResult lookup, baked directly into the query per the
    house rule -- returns None (caller returns 404) rather than fetch-then-check."""
    return ControlResult.query.filter_by(id=control_result_id, org_id=current_org_id()).first()


@review_bp.route('/control-results/<int:control_result_id>', methods=['GET'])
@roles_required(*ALL_ROLES)
def get_control_result(control_result_id):
    cr = _get_org_control_result(control_result_id)
    if not cr:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(cr.to_review_dict())


@review_bp.route('/control-results/<int:control_result_id>', methods=['PATCH'])
@roles_required(*REVIEWER_ROLES)
def update_control_result(control_result_id):
    cr = _get_org_control_result(control_result_id)
    if not cr:
        return jsonify({'error': 'Not found'}), 404

    data = request.get_json(silent=True) or {}

    if 'reviewer_status' in data:
        if data['reviewer_status'] not in REVIEWER_STATUSES:
            return jsonify({'error': f'reviewer_status must be one of: {", ".join(REVIEWER_STATUSES)}'}), 400
        cr.reviewer_status = data['reviewer_status']

    if 'reviewer_note' in data:
        cr.reviewer_note = data['reviewer_note']

    # A review is only stamped when the reviewer actually says something
    # about the finding -- reassigning or re-dating alone must not claim a
    # review happened.
    if 'reviewer_status' in data or 'reviewer_note' in data:
        cr.reviewed_by_id = current_user_id()
        cr.reviewed_at = datetime.utcnow()

    if 'assigned_to_id' in data:
        assigned_to_id = data['assigned_to_id']
        if assigned_to_id is not None:
            assignee = User.query.filter_by(id=assigned_to_id, org_id=current_org_id()).first()
            if not assignee:
                return jsonify({'error': 'assigned_to_id must be a user in your organization'}), 400
        cr.assigned_to_id = assigned_to_id

    if 'due_date' in data:
        due_date_raw = data['due_date']
        if due_date_raw is None:
            cr.due_date = None
        else:
            try:
                cr.due_date = datetime.strptime(due_date_raw, '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'due_date must be in YYYY-MM-DD format'}), 400

    if 'remediation_status' in data:
        remediation_status = data['remediation_status']
        if cr.status == 'Compliant':
            return jsonify({'error': 'remediation_status is not applicable to a Compliant control'}), 400
        if remediation_status not in REMEDIATION_STATUSES:
            return jsonify({'error': f'remediation_status must be one of: {", ".join(REMEDIATION_STATUSES)}'}), 400
        cr.remediation_status = remediation_status

    db.session.commit()
    return jsonify(cr.to_review_dict())


@review_bp.route('/control-results/<int:control_result_id>/evidence', methods=['POST'])
@roles_required(*EVIDENCE_UPLOAD_ROLES)
def upload_evidence(control_result_id):
    cr = _get_org_control_result(control_result_id)
    if not cr:
        return jsonify({'error': 'Not found'}), 404

    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    if not _evidence_file_allowed(file.filename):
        return jsonify({'error': f'Unsupported file type. Allowed: {", ".join(sorted(EVIDENCE_ALLOWED_EXTENSIONS))}'}), 400

    org_id = current_org_id()
    original_filename, stored_filename, filepath = _save_upload(file, org_id)

    evidence = EvidenceFile(
        org_id=org_id, control_result_id=cr.id, uploaded_by_id=current_user_id(),
        original_filename=original_filename, stored_filename=stored_filename,
        file_size=os.path.getsize(filepath),
    )
    db.session.add(evidence)
    db.session.commit()

    return jsonify({'success': True, 'evidence': evidence.to_dict()}), 201


@review_bp.route('/control-results/<int:control_result_id>/evidence', methods=['GET'])
@roles_required(*ALL_ROLES)
def list_evidence(control_result_id):
    cr = _get_org_control_result(control_result_id)
    if not cr:
        return jsonify({'error': 'Not found'}), 404

    files = EvidenceFile.query.filter_by(
        control_result_id=control_result_id, org_id=current_org_id()
    ).order_by(EvidenceFile.uploaded_at.desc()).all()
    return jsonify({'evidence': [f.to_dict() for f in files]})


@review_bp.route('/evidence/<int:evidence_id>/download', methods=['GET'])
@roles_required(*ALL_ROLES)
def download_evidence(evidence_id):
    evidence = EvidenceFile.query.filter_by(id=evidence_id, org_id=current_org_id()).first()
    if not evidence:
        return jsonify({'error': 'Not found'}), 404

    filepath = os.path.join(Config.UPLOAD_FOLDER, evidence.stored_filename)
    if not os.path.exists(filepath):
        return jsonify({'error': 'File missing from storage'}), 410

    response = send_file(filepath, as_attachment=True, download_name=evidence.original_filename)
    response.headers['Access-Control-Expose-Headers'] = 'Content-Disposition'
    return response


@review_bp.route('/evidence/<int:evidence_id>', methods=['DELETE'])
@roles_required(*EVIDENCE_DELETE_ROLES)
def delete_evidence(evidence_id):
    evidence = EvidenceFile.query.filter_by(id=evidence_id, org_id=current_org_id()).first()
    if not evidence:
        return jsonify({'error': 'Not found'}), 404

    filepath = os.path.join(Config.UPLOAD_FOLDER, evidence.stored_filename)
    try:
        os.remove(filepath)
    except FileNotFoundError:
        pass  # already gone -- don't let that block removing the DB row

    db.session.delete(evidence)
    db.session.commit()
    return jsonify({'success': True})


_SEVERITY_RANK = {'critical': 0, 'major': 1, 'minor': 2}


@review_bp.route('/assessments/<int:assessment_id>/remediation-plan', methods=['GET'])
@roles_required(*ALL_ROLES)
def remediation_plan(assessment_id):
    org_id = current_org_id()
    assessment = Assessment.query.filter_by(id=assessment_id, org_id=org_id).first()
    if not assessment:
        return jsonify({'error': 'Not found'}), 404

    framework_info = FRAMEWORKS.get(assessment.framework, {'controls': []})
    severity_by_control_id = {c['id']: c.get('severity', '') for c in framework_info['controls']}

    rows = ControlResult.query.filter_by(
        assessment_id=assessment_id, org_id=org_id
    ).filter(ControlResult.remediation_status.isnot(None)).all()

    today = date.today()
    items = []
    for cr in rows:
        is_overdue = bool(
            cr.due_date and cr.due_date < today and cr.remediation_status != 'closed'
        )
        severity = severity_by_control_id.get(cr.control_id, '')
        items.append({
            'control_result_id': cr.id,
            'control_id': cr.control_id,
            'control_name': cr.control_name,
            'severity': severity,
            'remediation_status': cr.remediation_status,
            'assigned_to_name': cr.assigned_to.name if cr.assigned_to else None,
            'due_date': cr.due_date.isoformat() if cr.due_date else None,
            'is_overdue': is_overdue,
            'reviewer_status': cr.reviewer_status,
        })

    items.sort(key=lambda i: (not i['is_overdue'], _SEVERITY_RANK.get(i['severity'], 99)))

    return jsonify({
        'assessment_id': assessment_id,
        'framework': assessment.framework,
        'items': items,
    })
