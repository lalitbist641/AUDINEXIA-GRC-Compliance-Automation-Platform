from datetime import datetime

from flask import Blueprint, jsonify

from models import Assessment, ControlResult, PolicyWatch, ROLES
from rbac import current_org_id, roles_required
from routes.scan_routes import reconstruct_control_dict
from scanning import FRAMEWORKS, framework_content_hash

assessment_bp = Blueprint('assessment', __name__)

ALL_ROLES = ROLES  # single source: models.ROLES, never a re-typed literal


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
    summary['audit_id'] = assessment.audit_id
    summary['content_hash'] = assessment.content_hash
    summary['framework_hash'] = assessment.framework_hash
    # Computed at read time rather than stored, so the answer always reflects
    # the framework definitions shipped today instead of whatever was cached
    # when someone last wrote to the row.
    summary['framework_definition_drift'] = bool(
        assessment.framework_hash and assessment.framework in FRAMEWORKS
        and assessment.framework_hash != framework_content_hash(assessment.framework)
    )
    summary['stored_document_available'] = bool(assessment.stored_filename)
    open_gaps = sum(1 for c in controls
                    if c['status'] != 'Language found'
                    and c.get('remediation_status') in ('open', 'in_progress'))
    summary['open_gaps'] = open_gaps
    return jsonify(summary)


@assessment_bp.route('/policy-documents', methods=['GET'])
@roles_required(*ALL_ROLES)
def policy_documents():
    """The document library: one row per distinct (filename, framework) pair
    with its latest scan, history count and review-cadence state.

    Derived entirely from stored assessments — there is no separate document
    table, and inventing one would mean a second source of truth for which
    policy versions exist. Size/upload time are read from the retained upload
    when it is still on disk, and reported as null when it is not, rather than
    showing a plausible-looking placeholder.
    """
    org_id = current_org_id()
    rows = (Assessment.query.filter_by(org_id=org_id)
            .order_by(Assessment.framework.asc(), Assessment.filename.asc(),
                      Assessment.created_at.desc()).all())

    watches = PolicyWatch.query.filter_by(org_id=org_id).all()
    watch_index = {(w.filename, w.framework): w for w in watches if w.is_active}
    now = datetime.utcnow()

    import os

    from config import Config

    grouped = {}
    for assessment in rows:
        key = (assessment.filename, assessment.framework)
        grouped.setdefault(key, []).append(assessment)

    documents = []
    for (filename, framework), history in grouped.items():
        latest = history[0]
        size_bytes = None
        stored_path = os.path.join(Config.UPLOAD_FOLDER, latest.stored_filename) \
            if latest.stored_filename else None
        if stored_path and os.path.exists(stored_path):
            size_bytes = os.path.getsize(stored_path)

        watch = watch_index.get((filename, framework))
        if watch:
            if not watch.next_due_at:
                cadence = 'unscheduled'
            elif watch.next_due_at < now:
                cadence = 'overdue'
            elif (watch.next_due_at - now).days <= 14:
                cadence = 'due_soon'
            else:
                cadence = 'current'
        else:
            cadence = 'unmonitored'

        open_gaps = (ControlResult.query
                     .filter_by(assessment_id=latest.id)
                     .filter(ControlResult.status != 'Language found')
                     .filter(ControlResult.remediation_status.in_(('open', 'in_progress')))
                     .count())

        documents.append({
            'filename': filename,
            'framework': framework,
            'framework_name': FRAMEWORKS[framework]['name'] if framework in FRAMEWORKS else framework,
            'format': (filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''),
            'size_bytes': size_bytes,
            'stored_document_available': bool(stored_path and os.path.exists(stored_path)),
            'latest_assessment_id': latest.id,
            'latest_score': latest.overall_score,
            'latest_scanned_at': latest.created_at.isoformat(),
            'latest_uploaded_by': latest.created_by.name if latest.created_by else None,
            'scan_count': len(history),
            'open_gaps': open_gaps,
            'compliant_count': latest.compliant_count,
            'partial_count': latest.partial_count,
            'non_compliant_count': latest.non_compliant_count,
            'vendor_id': latest.vendor_id,
            'vendor_name': latest.vendor.name if latest.vendor else None,
            'cadence': cadence,
            'watch_id': watch.id if watch else None,
            'next_due_at': watch.next_due_at.isoformat() if watch and watch.next_due_at else None,
            'framework_definition_drift': bool(
                latest.framework_hash and framework in FRAMEWORKS
                and latest.framework_hash != framework_content_hash(framework)),
        })

    order = {'overdue': 0, 'due_soon': 1, 'unmonitored': 2, 'current': 3, 'unscheduled': 4}
    documents.sort(key=lambda d: (order.get(d['cadence'], 5), -d['latest_score']))
    return jsonify({
        'documents': documents,
        'counts': {
            'total': len(documents),
            'overdue': sum(1 for d in documents if d['cadence'] == 'overdue'),
            'unmonitored': sum(1 for d in documents if d['cadence'] == 'unmonitored'),
            'framework_drift': sum(1 for d in documents if d['framework_definition_drift']),
        },
        'note': (
            'A document appears here once it has been scanned at least once. "unmonitored" means no '
            'review cadence is configured for it, which under most frameworks is itself a finding.'
        ),
    })
