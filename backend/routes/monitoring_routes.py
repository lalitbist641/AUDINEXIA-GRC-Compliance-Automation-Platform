"""Continuous compliance monitoring (report §12.7).

A PolicyWatch answers two questions from data the platform already holds:
  * freshness — has this policy been re-verified within its review interval?
  * drift — did the newest scan of this document move the score or flip any
    control status relative to the previous one?

Runs are triggered by an authenticated "Run Now", or by the `flask monitor
run-due` CLI (designed for cron / a Kubernetes CronJob). There is no
always-on scheduler in the request path on purpose: a background thread inside
a web worker silently double-runs under gunicorn's multiple workers and
silently stops on a restart, which is the wrong failure mode for something
whose whole job is telling you when evidence went stale.
"""

from datetime import datetime, timedelta

from flask import Blueprint, current_app, jsonify, request

from core.audit_trail import record
from core.monitoring import (
    DUE_SOON_WINDOW_DAYS,
    STATE_SEVERITY,
    compare_scans,
    freshness,
    next_due_after,
)
from core.scan_pipeline import ScanError, scan_assessment_row, scan_file
from extensions import db
from models import (
    ROLES,
    Assessment,
    ControlResult,
    MaturitySnapshot,
    PolicyWatch,
    PolicyWatchRun,
    WATCH_STATES,
)
from rbac import current_org_id, current_user_id, roles_required
from routes.scan_routes import _save_upload
from scanning import FRAMEWORKS, allowed_file, framework_content_hash

monitoring_bp = Blueprint('monitoring', __name__)

ALL_ROLES = ROLES  # single source: models.ROLES, never a re-typed literal
MANAGE_ROLES = ('org_admin', 'compliance_manager')
RUN_ROLES = ('org_admin', 'compliance_manager', 'auditor', 'member')

DEFAULT_INTERVAL_DAYS = 180


def _watch_dict(watch, now=None):
    now = now or datetime.utcnow()
    data = watch.to_dict()
    data['freshness'] = freshness(watch.next_due_at, now, watch.last_state)
    data['state_label'] = {
        'initial': 'Baseline recorded',
        'stable': 'Stable',
        'drift_up': 'Improved',
        'drift_down': 'Regressed',
        'control_flip': 'Controls changed',
        'framework_updated': 'Re-measured vs updated framework',
        'no_new_version': 'Not re-verified — no new document',
        'error': 'Run failed',
        'no_document': 'No document to scan',
    }.get(watch.last_state, watch.last_state or 'Never run')
    data['severity'] = STATE_SEVERITY.get(watch.last_state, 'info')
    data['latest_run'] = watch.runs[0].to_dict() if watch.runs else None
    return data


@monitoring_bp.route('/monitoring/watches', methods=['GET'])
@roles_required(*ALL_ROLES)
def list_watches():
    now = datetime.utcnow()
    watches = (PolicyWatch.query.filter_by(org_id=current_org_id())
               .order_by(PolicyWatch.next_due_at.asc().nulls_last()).all())
    items = [_watch_dict(w, now) for w in watches]
    items.sort(key=lambda d: (
        {'overdue': 0, 'due_soon': 1, 'current': 2, 'unscheduled': 3}[d['freshness']['status']],
        -(d['previous_score'] or 0) if d['last_state'] == 'drift_down' else 0,
        (d['name'] or '').lower(),
    ))
    return jsonify({
        'watches': items,
        'due_soon_window_days': DUE_SOON_WINDOW_DAYS,
        'states': list(WATCH_STATES),
        'default_interval_days': DEFAULT_INTERVAL_DAYS,
    })


@monitoring_bp.route('/monitoring/summary', methods=['GET'])
@roles_required(*ALL_ROLES)
def summary():
    """Header tiles + the "what needs attention today" list the dashboard
    surfaces. Derived live from watches rather than cached counters, so the
    numbers cannot disagree with the table underneath them."""
    now = datetime.utcnow()
    org_id = current_org_id()
    watches = PolicyWatch.query.filter_by(org_id=org_id, is_active=True).all()
    items = [_watch_dict(w, now) for w in watches]

    overdue = [i for i in items if i['freshness']['status'] == 'overdue']
    due_soon = [i for i in items if i['freshness']['status'] == 'due_soon']
    regressed = [i for i in items if i['last_state'] == 'drift_down']
    unverified = [i for i in items if i['last_state'] == 'no_new_version']

    assessments = Assessment.query.filter_by(org_id=org_id).all()
    stale_definitions = sum(1 for a in assessments if a.framework_hash and
                            a.framework_hash != framework_content_hash(a.framework)
                            if a.framework in FRAMEWORKS)

    drift_events = (PolicyWatchRun.query.filter_by(org_id=org_id)
                    .filter(PolicyWatchRun.run_at >= now - timedelta(days=90))
                    .filter(PolicyWatchRun.state.in_(('drift_down', 'drift_up', 'control_flip')))
                    .all())

    return jsonify({
        'watch_count': len(items),
        'overdue_count': len(overdue),
        'due_soon_count': len(due_soon),
        'regressed_count': len(regressed),
        'unverified_count': len(unverified),
        'drift_events_last_90_days': len(drift_events),
        'assessments_scored_against_superseded_frameworks': stale_definitions,
        'attention': [
            {
                'watch_id': i['id'], 'name': i['name'], 'framework': i['framework'],
                'reason': i['freshness']['label'], 'state': i['last_state'],
                'severity': i['severity'],
            }
            for i in items
            if i['freshness']['status'] in ('overdue', 'due_soon')
            or i['last_state'] in ('drift_down', 'no_new_version')
        ][:25],
        'honesty_note': (
            'Monitoring here watches the documents and scores already stored in this platform. '
            f'It does not connect to live systems, and {stale_definitions} historical assessment(s) '
            'were measured against framework definitions that have since changed — those scores '
            'are not comparable with a fresh scan until re-run.'
        ),
    })


@monitoring_bp.route('/monitoring/watches', methods=['POST'])
@roles_required(*MANAGE_ROLES)
def create_watch():
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    filename = (data.get('filename') or '').strip()
    framework = data.get('framework') or 'dpdpa'

    if not name:
        return jsonify({'error': 'name is required'}), 400
    if not filename:
        return jsonify({'error': 'filename is required — a watch tracks a specific document'}), 400
    if framework not in FRAMEWORKS:
        return jsonify({'error': f'Unknown framework: {framework}'}), 400
    try:
        interval = int(data.get('review_interval_days') or DEFAULT_INTERVAL_DAYS)
    except (TypeError, ValueError):
        return jsonify({'error': 'review_interval_days must be a whole number of days'}), 400
    if not 1 <= interval <= 3650:
        return jsonify({'error': 'review_interval_days must be between 1 and 3650'}), 400
    try:
        threshold = float(data.get('drift_threshold_points') or 5.0)
    except (TypeError, ValueError):
        return jsonify({'error': 'drift_threshold_points must be a number'}), 400
    if not 0 <= threshold <= 100:
        return jsonify({'error': 'drift_threshold_points must be between 0 and 100'}), 400

    if PolicyWatch.query.filter_by(org_id=current_org_id(), name=name).first():
        return jsonify({'error': 'A watch with this name already exists'}), 409

    # Anchor on the newest matching scan if there is one. The due date is
    # computed from *that scan's* timestamp, so adopting an existing 14-month-old
    # document starts out overdue instead of getting a fresh 180-day grace period
    # just because a watch was created today.
    anchor = (Assessment.query
              .filter_by(org_id=current_org_id(), framework=framework)
              .filter(Assessment.filename == filename)
              .order_by(Assessment.created_at.desc()).first())

    watch = PolicyWatch(
        org_id=current_org_id(), name=name, filename=filename, framework=framework,
        review_interval_days=interval, drift_threshold_points=threshold,
        created_by_id=current_user_id(), is_active=True,
    )
    if anchor:
        watch.last_run_at = anchor.created_at
        watch.last_score = anchor.overall_score
        watch.previous_score = None
        watch.last_state = 'initial'
        watch.last_assessment_id = anchor.id
        watch.last_content_hash = anchor.content_hash
        # Older rows predate hashing; fall back to the current hash so the very
        # first run is not spuriously reported as framework drift.
        watch.last_framework_hash = anchor.framework_hash or framework_content_hash(framework)
        watch.next_due_at = next_due_after(anchor.created_at, interval, datetime.utcnow())
    else:
        watch.next_due_at = datetime.utcnow()  # nothing on file: immediately due
    db.session.add(watch)
    db.session.flush()

    if anchor:
        db.session.add(PolicyWatchRun(
            org_id=current_org_id(), watch_id=watch.id, state='initial', trigger='baseline',
            current_assessment_id=anchor.id, current_score=anchor.overall_score,
            message=f'Baseline anchored on assessment #{anchor.id} '
                    f'({anchor.created_at.date().isoformat()}).',
        ))
    db.session.commit()
    record('monitoring.watch_create', 'policy_watch', watch.id,
           f'Watching {filename} against {framework} every {interval} days',
           {'filename': filename, 'framework': framework, 'interval_days': interval,
            'anchored_on_assessment': anchor.id if anchor else None})
    return jsonify({'success': True, 'watch': _watch_dict(watch)}), 201


@monitoring_bp.route('/monitoring/watches/<int:watch_id>', methods=['GET'])
@roles_required(*ALL_ROLES)
def get_watch(watch_id):
    watch = PolicyWatch.query.filter_by(id=watch_id, org_id=current_org_id()).first()
    if not watch:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({
        'watch': _watch_dict(watch),
        'runs': [r.to_dict() for r in watch.runs[:50]],
    })


@monitoring_bp.route('/monitoring/watches/<int:watch_id>', methods=['PATCH'])
@roles_required(*MANAGE_ROLES)
def update_watch(watch_id):
    watch = PolicyWatch.query.filter_by(id=watch_id, org_id=current_org_id()).first()
    if not watch:
        return jsonify({'error': 'Not found'}), 404
    data = request.get_json(silent=True) or {}
    changes = {}

    if 'review_interval_days' in data:
        try:
            interval = int(data['review_interval_days'])
        except (TypeError, ValueError):
            return jsonify({'error': 'review_interval_days must be a whole number of days'}), 400
        if not 1 <= interval <= 3650:
            return jsonify({'error': 'review_interval_days must be between 1 and 3650'}), 400
        watch.review_interval_days = interval
        changes['review_interval_days'] = interval
        # Re-derive the due date from the last verification so a shortened
        # interval takes effect immediately rather than at the next run.
        watch.next_due_at = next_due_after(watch.last_run_at, interval, datetime.utcnow())
    if 'drift_threshold_points' in data:
        try:
            threshold = float(data['drift_threshold_points'])
        except (TypeError, ValueError):
            return jsonify({'error': 'drift_threshold_points must be a number'}), 400
        if not 0 <= threshold <= 100:
            return jsonify({'error': 'drift_threshold_points must be between 0 and 100'}), 400
        watch.drift_threshold_points = threshold
        changes['drift_threshold_points'] = threshold
    if 'is_active' in data:
        watch.is_active = bool(data['is_active'])
        changes['is_active'] = watch.is_active
    if 'name' in data and (data['name'] or '').strip():
        watch.name = data['name'].strip()
        changes['name'] = watch.name

    db.session.commit()
    record('monitoring.watch_update', 'policy_watch', watch.id, f'Updated watch {watch.name}', changes)
    return jsonify({'success': True, 'watch': _watch_dict(watch)})


@monitoring_bp.route('/monitoring/watches/<int:watch_id>', methods=['DELETE'])
@roles_required('org_admin')
def delete_watch(watch_id):
    watch = PolicyWatch.query.filter_by(id=watch_id, org_id=current_org_id()).first()
    if not watch:
        return jsonify({'error': 'Not found'}), 404
    name = watch.name
    db.session.delete(watch)
    db.session.commit()
    # Recorded after the delete commit, matching every other handler here: the
    # trail should not claim a mutation that then rolled back.
    record('monitoring.watch_delete', 'policy_watch', watch_id, f'Deleted watch {name}',
           {'name': name})
    return jsonify({'success': True})


def _control_rows(assessment):
    return [{'id': cr.control_id, 'name': cr.control_name, 'status': cr.status, 'score': cr.score}
            for cr in assessment.control_results]


def _newest_scan(watch):
    """Latest stored scan of the document this watch tracks, or None.

    Matched on filename + framework because a watch tracks a *policy document*
    (which gets re-uploaded as new versions), not a single immutable assessment
    row. Filename matching is exact rather than fuzzy: two similarly named
    documents are different policies, and silently merging them would compare
    one document against another."""
    return (Assessment.query
            .filter_by(org_id=watch.org_id, framework=watch.framework)
            .filter(Assessment.filename == watch.filename)
            .order_by(Assessment.created_at.desc()).first())


def run_watch(watch, trigger='scheduled', upload=None, user_id=None):
    """Execute one monitoring check. Shared by the API and the CLI so a cron run
    and a manual "Run Now" can never behave differently.

    Returns (payload_dict, http_status).
    """
    started = datetime.utcnow()
    now = started
    baseline = None
    if watch.last_assessment_id:
        baseline = Assessment.query.filter_by(id=watch.last_assessment_id,
                                              org_id=watch.org_id).first()

    if upload is not None:
        # A fresh copy was supplied — the only input that can genuinely
        # re-verify a policy that may have been revised outside this platform.
        original_filename, stored_filename, filepath = _save_upload(upload, watch.org_id)
        actor_id = user_id or watch.created_by_id
        try:
            outcome = scan_file(
                filepath, original_filename, watch.framework, watch.org_id, actor_id,
                vendor_id=None, source='monitoring', parent_assessment=baseline,
            )
        except ScanError as exc:
            return ({'error': exc.message, **exc.detail}, exc.status)
        outcome['assessment'].stored_filename = stored_filename
        current_assessment = outcome['assessment']
        document_changed = outcome['content_hash'] != watch.last_content_hash
    else:
        newest = _newest_scan(watch)
        if newest is None:
            run = PolicyWatchRun(
                org_id=watch.org_id, watch_id=watch.id, state='no_document', trigger=trigger,
                message=f'No stored scan of "{watch.filename}" exists for framework '
                        f'{watch.framework}, so there is nothing to verify.',
                duration_ms=int((datetime.utcnow() - started).total_seconds() * 1000),
            )
            db.session.add(run)
            watch.last_run_at = now
            watch.last_state = 'no_document'
            db.session.commit()
            return ({'success': False, 'state': 'no_document', 'run': run.to_dict(),
                     'message': run.message,
                     'note': 'Run a scan of this policy document first, or upload the current '
                             'copy against this watch.'}, 409)

        try:
            # Re-score the newest stored document with the CURRENT framework
            # definitions. Deliberately not persisted: re-scanning the same
            # bytes produces a new measurement of the same evidence, and
            # storing it as a fresh assessment would make a stale document look
            # like it had been re-verified.
            outcome = scan_assessment_row(newest, persist=False)
        except ScanError as exc:
            run = PolicyWatchRun(
                org_id=watch.org_id, watch_id=watch.id, state='error', trigger=trigger,
                message=exc.message,
                duration_ms=int((datetime.utcnow() - started).total_seconds() * 1000),
            )
            db.session.add(run)
            watch.last_run_at = now
            watch.last_state = 'error'
            db.session.commit()
            return ({'error': exc.message, **exc.detail, 'run': run.to_dict()}, exc.status)

        current_assessment = newest
        document_changed = (
            outcome['content_hash'] != watch.last_content_hash
            or (baseline is not None and newest.id != baseline.id)
            or baseline is None
        )
        # Persist the freshly computed hashes so the next run compares against
        # what was actually measured now, but do NOT extend the due date unless
        # the check constitutes real verification (see clock rule below).
        outcome['content_hash_now'] = outcome['content_hash']

    framework_updated = bool(watch.last_framework_hash
                             and watch.last_framework_hash != outcome['framework_hash'])

    if not document_changed and not framework_updated:
        # Nothing to verify: same bytes, same yardstick, no new assessment.
        # The due date is deliberately left alone so the watch stays overdue.
        run = PolicyWatchRun(
            org_id=watch.org_id, watch_id=watch.id, state='no_new_version', trigger=trigger,
            baseline_assessment_id=watch.last_assessment_id,
            current_assessment_id=current_assessment.id if current_assessment else None,
            previous_score=watch.previous_score, current_score=watch.last_score,
            message=(
                f'Newest scan on file is still #{current_assessment.id} from '
                f'{current_assessment.created_at.date().isoformat()}; its text and the framework '
                'definitions are both unchanged, so this check verified nothing new.'
            ),
            duration_ms=int((datetime.utcnow() - started).total_seconds() * 1000),
        )
        db.session.add(run)
        watch.last_state = 'no_new_version'
        watch.consecutive_overdue_runs = (watch.consecutive_overdue_runs or 0) + 1
        db.session.commit()
        return ({
            'success': False, 'state': 'no_new_version',
            'severity': 'high', 'run': run.to_dict(), 'message': run.message,
            'verified': False,
            'next_step': 'Upload or scan the current version of this policy document to re-verify it.',
            'watch': _watch_dict(watch, now),
        }, 200)

    baseline_controls = _control_rows(baseline) if baseline else []
    comparison = compare_scans(
        baseline_controls, outcome['results'],
        baseline.overall_score if baseline else None,
        outcome['overall_score'], watch.drift_threshold_points,
    )
    state = comparison['state']
    if framework_updated and state in ('stable', 'initial'):
        # Same score, different yardstick: the position was re-measured, and
        # that only holds because we re-scored. Label it, don't call it 'stable'.
        state = 'framework_updated'
    if framework_updated:
        comparison['summary'] += (
            ' Framework definitions changed since the baseline scan, so part of this delta '
            'reflects the updated yardstick rather than the document alone.'
        )

    watch.previous_score = watch.last_score
    watch.last_score = outcome['overall_score']
    watch.last_state = state
    watch.last_run_at = now
    watch.last_assessment_id = current_assessment.id if current_assessment else watch.last_assessment_id
    watch.last_content_hash = outcome['content_hash']
    watch.last_framework_hash = outcome['framework_hash']
    watch.consecutive_overdue_runs = 0
    # Clock rule: a re-measurement of unchanged evidence against updated
    # definitions counts as verification (the position WAS re-checked today); a
    # check that found no new version does not (handled by the early return).
    watch.next_due_at = next_due_after(now, watch.review_interval_days, now)
    if upload is not None:
        # A newly uploaded copy under this watch is a real policy revision, so
        # record it as an assessment the user can open, export and review.
        current_assessment.framework_definition_drift = framework_updated
        current_assessment.parent_assessment_id = baseline.id if baseline else None

    run = PolicyWatchRun(
        org_id=watch.org_id, watch_id=watch.id, state=state, trigger=trigger,
        baseline_assessment_id=baseline.id if baseline else None,
        current_assessment_id=current_assessment.id if current_assessment else None,
        previous_score=watch.previous_score, current_score=watch.last_score,
        score_delta=comparison['score_delta'],
        controls_flipped=[
            {'control_id': f['control_id'], 'from': f['from_status'], 'to': f['to_status']}
            for f in (comparison['regressions'] + comparison['improvements'])
        ],
        message=comparison['summary'],
        duration_ms=int((datetime.utcnow() - started).total_seconds() * 1000),
    )
    db.session.add(run)

    # A drift run is the moment worth keeping a maturity reading for — that is
    # what turns a maturity level into a trend instead of a one-off claim.
    try:
        from routes.maturity_routes import snapshot_for_run

        snapshot_for_run(watch.org_id, watch.framework, 'monitoring_run')
    except Exception as exc:  # maturity is a side output; never fail a drift check over it
        current_app.logger.warning('maturity snapshot skipped during watch run: %s', exc)

    db.session.commit()
    record('monitoring.run', 'policy_watch', watch.id,
           f'{watch.name}: {state} ({comparison["score_delta"]:+.1f} pts)',
           {'state': state, 'score_delta': comparison['score_delta'],
            'framework_definition_drift': framework_updated, 'trigger': trigger})

    return ({
        'success': True,
        'verified': True,
        'state': state,
        'severity': STATE_SEVERITY.get(state, 'info'),
        'score_delta': comparison['score_delta'],
        'previous_score': watch.previous_score,
        'current_score': watch.last_score,
        'summary': comparison['summary'],
        'regressions': comparison['regressions'],
        'improvements': comparison['improvements'],
        'framework_definition_drift': framework_updated,
        'document_changed': document_changed,
        'current_assessment_id': current_assessment.id if current_assessment else None,
        'persisted_new_assessment': upload is not None,
        'watch': _watch_dict(watch, now),
    }, 200)


@monitoring_bp.route('/monitoring/watches/<int:watch_id>/run', methods=['POST'])
@roles_required(*RUN_ROLES)
def run_now(watch_id):
    """Re-check a watch. Optionally accepts a `file` part with the current copy
    of the policy; without one, the newest stored scan is re-measured against the
    current framework definitions."""
    watch = PolicyWatch.query.filter_by(id=watch_id, org_id=current_org_id()).first()
    if not watch:
        return jsonify({'error': 'Not found'}), 404

    upload = None
    if request.files:
        candidate = request.files.get('file')
        if candidate is not None and candidate.filename:
            if not allowed_file(candidate.filename):
                return jsonify({
                    'error': f'Unsupported file type. Allowed: {", ".join(sorted(Config.ALLOWED_EXTENSIONS))}',
                }), 400
            upload = candidate

    payload, status = run_watch(watch, trigger='manual', upload=upload,
                                user_id=current_user_id())
    return jsonify(payload), status


@monitoring_bp.route('/monitoring/due', methods=['GET'])
@roles_required(*ALL_ROLES)
def due_watches():
    """The list a scheduler consumes. Deliberately a pure read with no side
    effects, so an external cron can poll it safely."""
    now = datetime.utcnow()
    watches = (PolicyWatch.query.filter_by(org_id=current_org_id(), is_active=True)
               .filter(PolicyWatch.next_due_at <= now).all())
    return jsonify({
        'due': [{'id': w.id, 'name': w.name, 'framework': w.framework,
                 'next_due_at': w.next_due_at.isoformat(),
                 'overdue_days': max(0, (now - w.next_due_at).days)} for w in watches],
        'generated_at': now.isoformat(),
    })
