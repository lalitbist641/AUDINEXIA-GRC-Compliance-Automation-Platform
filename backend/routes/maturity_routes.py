"""Compliance maturity reporting (report §12.4).

The route layer owns DB access; core/maturity.py owns the ladder and its gates.
Every count below comes from records this platform actually holds, and each
gate reports the population it was judged on — so a reviewer can open the
underlying rows and check the claim, which is the point of a maturity number
in a compliance tool.
"""

from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request

from core.audit_trail import record
from core.maturity import LEVEL_LABELS, build, project_multi_framework
from extensions import db
from models import (
    ROLES,
    Assessment,
    Audit,
    ControlResult,
    EvidenceFile,
    Finding,
    MaturityAssessment,
    MaturitySnapshot,
    PolicyWatch,
)
from rbac import current_org_id, current_user_id, roles_required
from scanning import FRAMEWORKS, framework_content_hash

maturity_bp = Blueprint('maturity', __name__)

ALL_ROLES = ROLES  # single source: models.ROLES, never a re-typed literal
MANAGE_ROLES = ('org_admin', 'compliance_manager')

# A gap counts toward the maturity gates only while it is still open; a control
# a reviewer overrode to Compliant is no longer a gap, and counting it would
# punish honest review work.
GAP_STATUSES = ('Not found', 'Partially found')


def _latest_assessments_by_framework(org_id):
    """{framework: newest Assessment} for first-party documents only.

    Vendor assessments are excluded: mixing a vendor's policy quality into the
    organization's own maturity score is exactly the kind of unsupportable
    aggregate this project's report §11 warns against."""
    rows = (Assessment.query.filter_by(org_id=org_id, vendor_id=None)
            .order_by(Assessment.framework.asc(), Assessment.created_at.desc()).all())
    latest = {}
    for row in rows:
        latest.setdefault(row.framework, row)
    return latest


def gather_maturity_inputs(org_id, framework, include_portfolio=False):
    """Collect the raw counts core/maturity.py needs for one framework scope.

    Returns kwargs for compute_metrics(). Kept here (not in core/) because it is
    all query plumbing; the judgment stays in the testable module.
    """
    latest_assessment = (Assessment.query.filter_by(org_id=org_id, framework=framework,
                                                    vendor_id=None)
                         .order_by(Assessment.created_at.desc()).first())

    coverage = (latest_assessment.overall_score / 100.0) if latest_assessment else 0.0

    gap_rows = []
    if latest_assessment:
        gap_rows = [cr for cr in latest_assessment.control_results if cr.status in GAP_STATUSES]
    gap_count = len(gap_rows)

    gap_ids = {cr.id for cr in gap_rows}
    reviewed = sum(1 for cr in gap_rows if cr.reviewer_status in ('confirmed', 'overridden'))
    owned = sum(1 for cr in gap_rows if cr.assigned_to_id or cr.due_date)
    closed = sum(1 for cr in gap_rows if cr.remediation_status == 'closed')
    open_rows = [cr for cr in gap_rows if cr.remediation_status in ('open', 'in_progress')]
    today = datetime.utcnow().date()
    overdue = sum(1 for cr in open_rows if cr.due_date and cr.due_date < today)

    evidenced = 0
    if gap_ids:
        evidenced = (EvidenceFile.query
                     .filter(EvidenceFile.control_result_id.in_(gap_ids))
                     .with_entities(db.func.count(db.func.distinct(EvidenceFile.control_result_id)))
                     .scalar() or 0)

    # Distinct policy documents in scope for this framework, and how many of
    # them are covered by an active watch and still fresh.
    document_count = (db.session.query(Assessment.filename)
                      .filter_by(org_id=org_id, framework=framework, vendor_id=None)
                      .distinct().count())
    watches = PolicyWatch.query.filter_by(org_id=org_id, framework=framework,
                                          is_active=True).all()
    watched_names = {w.filename for w in watches}
    now = datetime.utcnow()
    overdue_names = {w.filename for w in watches if w.next_due_at and w.next_due_at < now}
    monitored = sum(1 for name in set(
        db.session.query(Assessment.filename).filter_by(org_id=org_id, framework=framework,
                                                         vendor_id=None).distinct().all()
    ) if name[0] in watched_names)
    unmonitored_overdue = 0  # a document with no watch is only "overdue" if a prior scan exists
    if document_count and not watches:
        # No monitoring configured at all: if the newest scan is older than the
        # default interval, count every document as overdue — that is the
        # honest reading of "not re-verified within a defined interval".
        if latest_assessment and (now - latest_assessment.created_at) > timedelta(days=180):
            unmonitored_overdue = document_count

    # Assessment data points: maturity at level 4 requires a trend, and a trend
    # needs more than one measurement of the same scope.
    data_points = (Assessment.query.filter_by(org_id=org_id, framework=framework, vendor_id=None)
                   .count())

    score_delta = None
    if data_points >= 2:
        recent = (Assessment.query.filter_by(org_id=org_id, framework=framework, vendor_id=None)
                  .order_by(Assessment.created_at.desc()).limit(2).all())
        if len(recent) == 2:
            score_delta = round(recent[0].overall_score - recent[1].overall_score, 1)

    finding_rows = Finding.query.join(Audit, Finding.audit_id == Audit.id).filter(
        Finding.org_id == org_id).all()
    finding_count = len(finding_rows)
    resolved = sum(1 for f in finding_rows if f.status in ('resolved', 'closed', 'accepted_risk'))
    overdue_findings = sum(1 for f in finding_rows
                           if f.status not in ('resolved', 'closed', 'accepted_risk')
                           and f.due_date and f.due_date < today)

    framework_drift = 1 if (latest_assessment and latest_assessment.framework_hash
                            and latest_assessment.framework_hash
                            != framework_content_hash(framework)) else 0

    return {
        'coverage_fraction': coverage,
        'gap_count': gap_count,
        'reviewed_gap_count': reviewed,
        'evidenced_gap_count': evidenced,
        'owned_gap_count': owned,
        'closed_gap_count': closed,
        'overdue_gap_count': overdue,
        'document_count': document_count,
        'monitored_document_count': monitored,
        'overdue_document_count': overdue_document_count(document_count, overdue_names,
                                                          unmonitored_overdue),
        'assessment_data_points': data_points,
        'finding_count': finding_count,
        'resolved_finding_count': resolved,
        'overdue_finding_count': overdue_findings,
        'framework_drift_count': framework_drift,
        'latest_score_delta': score_delta,
        'latest_assessment_id': latest_assessment.id if latest_assessment else None,
    }


def overdue_document_count(document_count, overdue_names, unmonitored_overdue):
    if document_count and not overdue_names and unmonitored_overdue:
        return unmonitored_overdue
    return min(len(overdue_names), document_count)


def evaluate_framework(org_id, framework):
    """One framework's maturity, merged with whatever the org has recorded
    (claim, target, approval, snapshot history)."""
    raw = gather_maturity_inputs(org_id, framework)
    payload = {k: v for k, v in raw.items() if k != 'latest_assessment_id'}
    result = build(**payload)

    row = MaturityAssessment.query.filter_by(org_id=org_id, framework=framework).first()
    result['framework'] = framework
    result['framework_name'] = FRAMEWORKS[framework]['name']
    result['latest_assessment_id'] = raw['latest_assessment_id']
    result['record_id'] = row.id if row else None
    result['claimed_level'] = row.current_level if row else None
    result['claimed_level_label'] = LEVEL_LABELS.get(row.current_level) if row else None
    result['target_level'] = row.target_level if row else 3
    result['target_level_label'] = LEVEL_LABELS.get(row.target_level if row else 3)
    result['self_assessment_notes'] = row.self_assessment_notes if row else None
    result['approved_by_name'] = (row.approved_by.name if row and row.approved_by else None)
    result['approved_at'] = (row.approved_at.isoformat() if row and row.approved_at else None)
    result['review_due_at'] = (row.review_due_at.isoformat() if row and row.review_due_at else None)
    result['snapshots'] = [s.to_dict() for s in (row.snapshots[:12] if row else [])]
    result['input_counts'] = {
        'open_or_partial_controls_on_latest_scan': raw['gap_count'],
        'reviewed': raw['reviewed_gap_count'],
        'with_evidence': raw['evidenced_gap_count'],
        'with_owner_or_due_date': raw['owned_gap_count'],
        'remediated_closed': raw['closed_gap_count'],
        'overdue_remediations': raw['overdue_gap_count'],
        'documents_in_scope': raw['document_count'],
        'documents_under_review_cadence': raw['monitored_document_count'],
        'documents_overdue': raw['overdue_document_count'],
        'assessments_for_trend': raw['assessment_data_points'],
        'audit_findings': raw['finding_count'],
        'audit_findings_resolved': raw['resolved_finding_count'],
    }
    result['limitation'] = (
        'Self-assessment aid derived from this platform\'s own records. Not an ISO/IEC 33000 '
        '(SPICE) appraisal: the inputs are document coverage plus workflow history, and no '
        'independent process verification has taken place.'
    )
    # Re-apply the claim comparison now that we know whether a claim exists.
    if row:
        recomputed = build(claimed_level=row.current_level, target_level=row.target_level, **payload)
        result['claim_overstates'] = recomputed['claim_overstates']
        result['claim_gap_note'] = recomputed['claim_gap_note']
        result['levels_to_target'] = recomputed['levels_to_target']
        # A claim the evidence does not support is surfaced, never silently
        # adopted: derived_level stays the reported figure.
        result['capped_by_evidence'] = row.current_level > result['derived_level']
    return result


@maturity_bp.route('/maturity', methods=['GET'])
@roles_required(*ALL_ROLES)
def list_maturity():
    """Per-framework maturity for every framework with any assessment, plus the
    portfolio view."""
    org_id = current_org_id()
    latest = _latest_assessments_by_framework(org_id)
    rows = MaturityAssessment.query.filter_by(org_id=org_id).all()
    frameworks = sorted(set(list(latest.keys()) + [r.framework for r in rows if
                               r.framework in FRAMEWORKS]))

    results = [evaluate_framework(org_id, fw) for fw in frameworks]
    portfolio = project_multi_framework(results) if results else None
    return jsonify({
        'frameworks': results,
        'portfolio': portfolio,
        'level_labels': LEVEL_LABELS,
        'generated_at': datetime.utcnow().isoformat(),
        'empty': not results,
        'note': (
            'Frameworks with no assessment of your own documents are omitted rather than shown '
            'as level 1 — an unmeasured framework is unknown, not immature.'
            if len(results) < len(FRAMEWORKS) else ''
        ),
    })


@maturity_bp.route('/maturity/<framework>', methods=['GET'])
@roles_required(*ALL_ROLES)
def get_maturity(framework):
    if framework not in FRAMEWORKS:
        return jsonify({'error': f'Unknown framework: {framework}'}), 400
    return jsonify(evaluate_framework(current_org_id(), framework))


@maturity_bp.route('/maturity/<framework>', methods=['PATCH'])
@roles_required(*MANAGE_ROLES)
def update_maturity(framework):
    """Record the organization's claimed level, target, notes and approval.

    Writes never change derived_level: a human asserting "we are Defined" is a
    claim to be evidenced, not evidence."""
    if framework not in FRAMEWORKS:
        return jsonify({'error': f'Unknown framework: {framework}'}), 400
    org_id = current_org_id()
    data = request.get_json(silent=True) or {}

    row = MaturityAssessment.query.filter_by(org_id=org_id, framework=framework).first()
    if row is None:
        row = MaturityAssessment(org_id=org_id, framework=framework, current_level=1,
                                 target_level=3)
        db.session.add(row)
        db.session.flush()

    changes = {}
    if 'current_level' in data:
        try:
            level = int(data['current_level'])
        except (TypeError, ValueError):
            return jsonify({'error': 'current_level must be an integer 1-5'}), 400
        if level not in LEVEL_LABELS:
            return jsonify({'error': 'current_level must be between 1 and 5'}), 400
        row.current_level = level
        changes['current_level'] = level
        # Claiming a level above the recorded target leaves a nonsense row
        # (target 3, current 5), so the target follows the claim upward.
        if row.target_level < level:
            row.target_level = level
            changes['target_level'] = level
    if 'target_level' in data:
        try:
            target = int(data['target_level'])
        except (TypeError, ValueError):
            return jsonify({'error': 'target_level must be an integer 1-5'}), 400
        if target not in LEVEL_LABELS:
            return jsonify({'error': 'target_level must be between 1 and 5'}), 400
        if target < row.current_level:
            return jsonify({'error': 'target_level cannot be below the current level'}), 400
        row.target_level = target
        changes['target_level'] = target
    if 'self_assessment_notes' in data:
        row.self_assessment_notes = (data['self_assessment_notes'] or '').strip() or None
        changes['self_assessment_notes'] = bool(row.self_assessment_notes)

    if data.get('approve'):
        row.approved_by_id = current_user_id()
        row.approved_at = datetime.utcnow()
        row.review_due_at = datetime.utcnow() + timedelta(days=365)
        changes['approved'] = True
    if 'review_due_at' in data:
        if data['review_due_at'] in (None, ''):
            row.review_due_at = None
        else:
            try:
                row.review_due_at = datetime.strptime(data['review_due_at'][:10], '%Y-%m-%d')
            except (TypeError, ValueError):
                return jsonify({'error': 'review_due_at must be YYYY-MM-DD'}), 400
        changes['review_due_at'] = data['review_due_at']

    # Refresh the evidence-derived fields in the same write, and append a
    # snapshot so the trend has a data point for the decision that was just made.
    result = build(**{k: v for k, v in gather_maturity_inputs(org_id, framework).items()
                      if k != 'latest_assessment_id'})
    row.derived_level = result['derived_level']
    row.derived_score = result['derived_score']
    row.level_rationale = {
        'blockers': result['blockers'],
        'dimensions': result['metrics'],
        'methodology': result['methodology'],
    }
    row.capped_by_evidence = row.current_level > result['derived_level']
    db.session.add(MaturitySnapshot(
        org_id=org_id, maturity_id=row.id, level=result['derived_level'],
        score=result['derived_score'], metrics=result['metrics'], trigger='claim_update',
    ))
    db.session.commit()
    record('maturity.update', 'maturity_assessment', row.id,
           f'{framework} maturity claim set to {LEVEL_LABELS.get(row.current_level)}', changes)
    return jsonify({'success': True, 'maturity': evaluate_framework(org_id, framework)})


@maturity_bp.route('/maturity/<framework>/recalculate', methods=['POST'])
@roles_required(*MANAGE_ROLES)
def recalculate(framework):
    """Re-derive from current records and append a trend point.

    Explicit rather than automatic: silently rewriting the stored derived level
    on every read would make the trend chart meaningless, since history would
    always agree with today."""
    if framework not in FRAMEWORKS:
        return jsonify({'error': f'Unknown framework: {framework}'}), 400
    org_id = current_org_id()
    snapshot_for_run(org_id, framework, 'recalculate')
    db.session.commit()
    record('maturity.recalculate', 'maturity_assessment', None,
           f'Recalculated {framework} maturity from current records', {'framework': framework})
    return jsonify({'success': True, 'maturity': evaluate_framework(org_id, framework)})


def snapshot_for_run(org_id, framework, trigger):
    """Create/refresh the stored row and append a snapshot. Used by monitoring
    runs and the explicit recalculation endpoint.

    Caller owns the commit — this must not commit on its own, or a monitoring
    run that later failed would still have persisted a maturity write."""
    row = MaturityAssessment.query.filter_by(org_id=org_id, framework=framework).first()
    if row is None:
        row = MaturityAssessment(org_id=org_id, framework=framework, current_level=1,
                                 target_level=3)
        db.session.add(row)
        db.session.flush()

    payload = {k: v for k, v in gather_maturity_inputs(org_id, framework).items()
               if k != 'latest_assessment_id'}
    result = build(claimed_level=row.current_level, target_level=row.target_level, **payload)
    row.derived_level = result['derived_level']
    row.derived_score = result['derived_score']
    row.level_rationale = {
        'blockers': result['blockers'],
        'dimensions': result['metrics'],
        'methodology': result['methodology'],
    }
    row.capped_by_evidence = row.current_level > result['derived_level']
    snapshot = MaturitySnapshot(
        org_id=org_id, maturity_id=row.id, level=result['derived_level'],
        score=result['derived_score'], metrics=result['metrics'], trigger=trigger,
    )
    db.session.add(snapshot)
    return row, snapshot


@maturity_bp.route('/maturity/<framework>/trend', methods=['GET'])
@roles_required(*ALL_ROLES)
def trend(framework):
    if framework not in FRAMEWORKS:
        return jsonify({'error': f'Unknown framework: {framework}'}), 400
    row = MaturityAssessment.query.filter_by(org_id=current_org_id(), framework=framework).first()
    points = [{'taken_at': s.taken_at.isoformat(), 'level': s.level,
               'level_label': LEVEL_LABELS.get(s.level, str(s.level)), 'score': s.score,
               'trigger': s.trigger} for s in reversed(row.snapshots)] if row else []
    return jsonify({
        'framework': framework,
        'points': points,
        'note': (
            'Snapshots are appended on claim updates, explicit recalculations and monitoring runs. '
            'A single point is not a trend; two or more are needed before the direction means '
            'anything.'
        ),
    })
