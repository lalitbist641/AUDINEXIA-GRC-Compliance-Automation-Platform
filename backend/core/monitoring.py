"""Continuous-monitoring logic: re-verification scheduling and score drift
(report §12.7).

Two separate questions get two separate answers here, because conflating them
is how compliance tools end up reporting false comfort:

1. "Has this policy been re-verified recently enough?" — a *freshness*
   question, answered from the timestamp of the newest scan of that document,
   never from the timestamp of the last monitoring run. Running a watch that
   finds no new evidence must not reset the clock, or a stale policy would
   look perpetually current.

2. "Has the compliance position changed?" — a *drift* question, answered by
   comparing the newest scan of a document against the previous one: weighted
   score movement plus per-control status transitions. A score can stay flat
   while a critical control flips from Compliant to Non-Compliant, so per-
   control transitions are reported independently of the score delta and can
   raise a drift flag on their own.
"""

from scanning import FRAMEWORKS, framework_content_hash

STATUS_ORDER = {'Not found': 0, 'Partially found': 1, 'Language found': 2}
DUE_SOON_WINDOW_DAYS = 14


def assessment_framework_drift(assessment):
    """True when a stored assessment was scored against a framework definition
    that no longer matches the shipped one (report §12.7's "a framework's
    underlying requirements change" case).

    Comparison is by content hash over the scoring-relevant fields, so a
    cosmetic edit to the definitions (icon, color, wording of why_matters)
    does not invalidate historical scores.
    """
    if not assessment.framework_hash or assessment.framework not in FRAMEWORKS:
        # No recorded hash (assessment created before Phase 7) or an unknown
        # framework — cannot claim drift either way, so report False rather
        # than guessing.
        return False
    return assessment.framework_hash != framework_content_hash(assessment.framework)


def compare_scans(baseline_controls, current_controls, baseline_score, current_score,
                  drift_threshold_points=5.0):
    """Compare two per-control result sets (same framework) and classify drift.

    baseline_controls/current_controls: iterables of dicts with at least
    'id', 'name', 'status', 'score'.

    Returns a dict with the score delta, per-control transitions, and the
    resulting state. Only transitions that a reader can verify in the two
    scans are reported — nothing here extrapolates or smooths.
    """
    base = {c['id']: c for c in baseline_controls}
    curr = {c['id']: c for c in current_controls}

    score_delta = round((current_score or 0) - (baseline_score or 0), 1)

    regressions = []
    improvements = []
    for control_id in sorted(set(base) & set(curr)):
        old, new = base[control_id], curr[control_id]
        old_rank = STATUS_ORDER.get(old['status'], 0)
        new_rank = STATUS_ORDER.get(new['status'], 0)
        entry = {
            'control_id': control_id,
            'control_name': new.get('name') or old.get('name'),
            'from_status': old['status'],
            'to_status': new['status'],
            'from_score': old.get('score'),
            'to_score': new.get('score'),
            'score_delta': round((new.get('score') or 0) - (old.get('score') or 0), 1),
        }
        if new_rank < old_rank:
            regressions.append(entry)
        elif new_rank > old_rank:
            improvements.append(entry)

    added = [{'control_id': cid, 'control_name': curr[cid].get('name'), 'status': curr[cid]['status']}
             for cid in sorted(set(curr) - set(base))]
    removed = [{'control_id': cid, 'control_name': base[cid].get('name')}
               for cid in sorted(set(base) - set(curr))]

    flipped = bool(regressions or improvements)
    score_drift = abs(score_delta) >= abs(drift_threshold_points or 0)

    if not base:
        state = 'initial'
    elif score_delta <= -abs(drift_threshold_points) and not flipped:
        state = 'drift_down'
    elif score_delta >= abs(drift_threshold_points) and not flipped:
        state = 'drift_up'
    elif regressions:
        # A regression is always reportable, even when compensating
        # improvements hold the weighted score flat.
        state = 'drift_down'
    elif score_drift:
        state = 'drift_up' if score_delta > 0 else 'drift_down'
    elif flipped:
        state = 'control_flip'
    else:
        state = 'stable'

    return {
        'state': state,
        'score_delta': score_delta,
        'score_drift': score_drift,
        'status_flip': flipped,
        'regressions': regressions,
        'improvements': improvements,
        'added_controls': added,
        'removed_controls': removed,
        'summary': _summarize(state, score_delta, regressions, improvements, added, removed),
    }


STATE_LABELS = {
    'initial': 'Baseline recorded',
    'stable': 'Stable — no material change',
    'drift_up': 'Improved since last verification',
    'drift_down': 'Regressed since last verification',
    'control_flip': 'Control statuses changed (net score roughly flat)',
    'framework_updated': 'Re-measured against updated framework definitions',
    'no_new_version': 'No newer scan available to verify',
    'error': 'Could not run',
}

STATE_SEVERITY = {
    'no_new_version': 'high',
    'framework_updated': 'medium',
    'drift_down': 'high',
    'control_flip': 'medium',
    'initial': 'info',
    'stable': 'low',
    'drift_up': 'info',
    'error': 'medium',
}


def _summarize(state, delta, regressions, improvements, added, removed):
    parts = []
    if delta:
        parts.append(f"weighted score {'+' if delta > 0 else ''}{delta} points")
    else:
        parts.append('weighted score unchanged')
    if regressions:
        parts.append(f"{len(regressions)} control(s) regressed")
    if improvements:
        parts.append(f"{len(improvements)} control(s) improved")
    if added:
        parts.append(f"{len(added)} control(s) newly in scope")
    if removed:
        parts.append(f"{len(removed)} control(s) no longer in the framework")
    return f"{STATE_LABELS.get(state, state)}: " + ', '.join(parts) + '.'


def freshness(next_due_at, now, last_state=None):
    """Classify how overdue a watch is. Returns a dict for API/JSON display.

    'due_soon' rather than only 'overdue' matters operationally: a policy that
    is verified every 180 days and is 175 days old needs the same attention as
    one that is 181 days old, but only the latter trips a red flag.
    """
    if not next_due_at:
        return {'status': 'unscheduled', 'label': 'Not yet scheduled', 'days_from_due': None}
    delta_days = (next_due_at - now).total_seconds() / 86400
    if delta_days < 0:
        status = 'overdue'
    elif delta_days <= DUE_SOON_WINDOW_DAYS:
        status = 'due_soon'
    else:
        status = 'current'
    return {
        'status': status,
        'label': {
            'overdue': f'Overdue by {abs(int(delta_days))} day(s)',
            'due_soon': f'Due in {int(delta_days)} day(s)',
            'current': f'Due in {int(delta_days)} day(s)',
        }[status],
        'days_from_due': round(delta_days, 1),
        'last_state': last_state,
    }


def next_due_after(last_verified_at, interval_days, now):
    """Anchor the next due date on when the *document* was last scanned.

    Anchoring on the run time instead would let a watch that keeps finding no
    new evidence push its own due date forward forever.
    """
    from datetime import timedelta

    if not last_verified_at or not interval_days:
        return None
    return last_verified_at + timedelta(days=int(interval_days))
