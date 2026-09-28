"""Shared scan pipeline (report §12.8 module split).

The scan logic lives here rather than in the route module because three
different entry points need the identical pipeline: an analyst scan
(scan_routes), a vendor document assessment (vendor_routes), and a scheduled
monitoring re-scan (monitoring_routes). Duplicating the extract → analyze →
score → persist sequence three times is exactly how the "0% fabricated report"
class of bug was introduced in the first place, so there is one implementation
and each caller only decides *who* the scan is attributed to.
"""

from datetime import datetime

from extensions import db
from models import Assessment, ControlResult
from scanning import (
    FRAMEWORKS,
    analyze_control,
    calculate_weighted_score,
    extract_text,
    framework_content_hash,
    is_valid_extracted_text,
    text_hash,
)


class ScanError(Exception):
    """Raised for a *rejected input* (bad file, unreadable document).

    Carries the HTTP status the route should return, so each entry point
    renders the same message instead of paraphrasing it.
    """

    def __init__(self, message, status=400, detail=None):
        super().__init__(message)
        self.message = message
        self.status = status
        self.detail = detail or {}


def scan_file(filepath, original_filename, framework, org_id, user_id,
              vendor_id=None, source='manual', parent_assessment=None,
              persist=True):
    """Extract, analyze, score and (optionally) persist one document.

    Returns a dict: assessment (the ORM row or None), results (per-control
    dicts), overall_score, counts, content_hash, framework_hash,
    framework_definition_drift.

    Raises ScanError when the file cannot be read as text — callers must never
    continue to scoring after that, which is the whole point of
    is_valid_extracted_text() (see the long comment above it in scanning.py).
    """
    if framework not in FRAMEWORKS:
        raise ScanError(f'Framework "{framework}" not supported', 400,
                        {'supported': list(FRAMEWORKS.keys())})

    policy_text = extract_text(filepath)
    if not is_valid_extracted_text(policy_text):
        raise ScanError(
            'Could not extract readable text from this file. It may be image-only '
            '(scanned, no text layer), password-protected, or corrupted.',
            400,
            {'extraction_detail': policy_text},
        )

    framework_info = FRAMEWORKS[framework]
    results = [analyze_control(policy_text, ctrl) for ctrl in framework_info['controls']]
    overall_score = calculate_weighted_score(results)

    compliant_count = sum(1 for r in results if r['status'] == 'Compliant')
    partial_count = sum(1 for r in results if r['status'] == 'Partially Compliant')
    non_compliant_count = sum(1 for r in results if r['status'] == 'Non-Compliant')

    # The hash is taken over the framework definition *as it exists now*, at the
    # moment of scoring — that is what makes it a valid yardstick for later
    # re-scans and for detecting that requirements changed underneath an
    # historical score.
    fw_hash = framework_content_hash(framework)
    drift = bool(
        parent_assessment is not None
        and parent_assessment.framework_hash
        and parent_assessment.framework_hash != fw_hash
    )

    assessment = None
    if persist:
        report_id = datetime.now().strftime('AUD-%Y%m%d-%H%M%S')
        assessment = Assessment(
            org_id=org_id, user_id=user_id, framework=framework,
            filename=original_filename, overall_score=overall_score,
            compliant_count=compliant_count, partial_count=partial_count,
            non_compliant_count=non_compliant_count, report_id=report_id,
            vendor_id=vendor_id, source=source,
            content_hash=text_hash(policy_text), framework_hash=fw_hash,
            parent_assessment_id=parent_assessment.id if parent_assessment else None,
            framework_definition_drift=drift,
        )
        db.session.add(assessment)
        db.session.flush()

        for r in results:
            cr = ControlResult(
                org_id=org_id, assessment_id=assessment.id, control_id=r['id'],
                control_name=r['name'], score=r['score'], status=r['status'],
                evidence_text=r['evidence'], missing_phrases=r['missing_phrases'],
                found_phrases=r['found_phrases'],
                remediation_status=(None if r['status'] == 'Compliant' else 'open'),
            )
            db.session.add(cr)
            db.session.flush()  # populate cr.id so it can be returned to the client
            r['control_result_id'] = cr.id
            r['assessment_id'] = assessment.id
    else:
        # Non-persisted scans (a monitoring re-scan that turned out identical to
        # its baseline) still need stable control references for the UI.
        for r in results:
            r['control_result_id'] = None
            r['assessment_id'] = None

    return {
        'assessment': assessment,
        'results': results,
        'overall_score': overall_score,
        'compliant_count': compliant_count,
        'partial_count': partial_count,
        'non_compliant_count': non_compliant_count,
        'content_hash': text_hash(policy_text),
        'framework_hash': fw_hash,
        'framework_definition_drift': drift,
        'extracted_characters': len(policy_text),
    }


def scan_assessment_row(assessment, framework=None, persist=True):
    """Re-score a document already stored on disk (the monitoring path).

    Reads the stored file rather than asking the caller to re-upload, so a
    scheduled check measures the same bytes the analyst measured. Returns the
    same shape as scan_file().
    """
    import os

    from config import Config

    if not assessment.stored_filename:
        raise ScanError(
            'The source assessment did not retain an upload to re-scan, so no drift check is possible. '
            'Re-upload the policy document to establish a new baseline.',
            409,
            {'reason': 'no_stored_file'},
        )
    filepath = os.path.join(Config.UPLOAD_FOLDER, assessment.stored_filename)
    if not os.path.exists(filepath):
        raise ScanError(
            'The stored policy document is no longer on disk (uploads directory was cleared or the '
            'assessment predates file retention). Upload a fresh copy to re-establish a baseline.',
            409,
            {'reason': 'stored_file_missing'},
        )
    return scan_file(
        filepath, assessment.filename, framework or assessment.framework,
        assessment.org_id, assessment.user_id,
        vendor_id=assessment.vendor_id, source='monitoring',
        parent_assessment=assessment, persist=persist,
    )
