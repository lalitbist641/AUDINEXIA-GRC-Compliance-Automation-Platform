"""Non-HTTP entry points for continuous monitoring.

Kept separate from routes/monitoring_routes.py because the CLI has no request
context: no JWT claims, no `g`, no current_org_id(). Splitting it out makes that
constraint visible instead of implicit — `run_due_watches` iterates every
organization, which an HTTP handler must never do.

This module is what a cron job or Kubernetes CronJob runs:

    flask monitor run-due

It is safe to run on any schedule: a watch just checked is not due, and a check
that finds nothing new is recorded as `no_new_version` without resetting the
due date (see core/monitoring.py for why that distinction is the whole point).
"""

from datetime import datetime

from extensions import db
from models import PolicyWatch


def list_due(org_id=None, now=None):
    now = now or datetime.utcnow()
    query = (PolicyWatch.query
             .filter_by(is_active=True)
             .filter(PolicyWatch.next_due_at.isnot(None))
             .filter(PolicyWatch.next_due_at <= now))
    if org_id:
        query = query.filter_by(org_id=org_id)
    watches = query.order_by(PolicyWatch.next_due_at.asc()).all()
    return [{
        'id': w.id,
        'org_id': w.org_id,
        'name': w.name,
        'framework': w.framework,
        'state': w.last_state,
        'next_due_at': w.next_due_at.isoformat(),
        'overdue_days': (now - w.next_due_at).days,
    } for w in watches]


def run_due_watches(org_id=None, limit=50, now=None):
    """Run every due watch. Returns a summary dict (also what the CLI prints).

    One transaction per watch rather than one for the whole pass: a failure on
    vendor B's policy document must not roll back the drift finding already
    recorded for vendor A, and partial progress is strictly more useful than a
    rolled-back pass.
    """
    now = now or datetime.utcnow()
    query = (PolicyWatch.query
             .filter_by(is_active=True)
             .filter(PolicyWatch.next_due_at.isnot(None))
             .filter(PolicyWatch.next_due_at <= now))
    if org_id:
        query = query.filter_by(org_id=org_id)
    watches = query.order_by(PolicyWatch.next_due_at.asc()).limit(limit).all()

    from routes.monitoring_routes import run_watch

    summary = {'ran': 0, 'skipped': 0, 'regressions': 0, 'improvements': 0,
               'unverified': 0, 'errors': 0, 'details': []}
    for watch in watches:
        try:
            payload, status = run_watch(watch, trigger='scheduled')
        except Exception as exc:  # a bad document must not stop the whole pass
            db.session.rollback()
            summary['errors'] += 1
            summary['details'].append({'watch_id': watch.id, 'state': 'error',
                                       'error': str(exc), 'score_delta': None})
            continue

        state = payload.get('state', 'error')
        entry = {
            'watch_id': watch.id,
            'watch_name': watch.name,
            'org_id': watch.org_id,
            'state': state,
            'score_delta': payload.get('score_delta'),
            'http_status': status,
            'message': payload.get('summary') or payload.get('message') or payload.get('error'),
        }
        summary['details'].append(entry)
        if not payload.get('success'):
            summary['skipped'] += 1
        else:
            summary['ran'] += 1
        if state == 'drift_down':
            summary['regressions'] += 1
        elif state in ('drift_up',):
            summary['improvements'] += 1
        elif state == 'no_new_version':
            summary['unverified'] += 1
        elif state == 'error':
            summary['errors'] += 1
    return summary


def snapshot_all_maturity(framework=None):
    """Append a maturity snapshot for each org+framework with an admin-visible
    maturity record. Used by a nightly job so the trend chart moves even when
    nobody clicks."""
    from models import MaturityAssessment
    from routes.maturity_routes import snapshot_for_run

    query = MaturityAssessment.query
    if framework:
        query = query.filter_by(framework=framework)
    written = 0
    orgs = set()
    for row in query.all():
        snapshot_for_run(row.org_id, row.framework, 'scheduled')
        written += 1
        orgs.add(row.org_id)
    db.session.commit()
    return {'written': written, 'orgs': len(orgs)}
