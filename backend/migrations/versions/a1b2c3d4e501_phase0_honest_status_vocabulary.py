"""Phase 0 (2.5): honest scanner status vocabulary

The scanner counts required phrases; it does not judge compliance. Its status
labels were renamed from Compliant / Partially Compliant / Non-Compliant to
Language found / Partially found / Not found. Application code compares against
the new strings, so rows persisted under the old vocabulary must be rewritten
or every old assessment would silently fall into the wrong branch (e.g. a
"Compliant" control would be treated as a gap, and the remediation guard would
stop recognising it).

Rewrites:
  * control_results.status
  * policy_watch_runs.controls_flipped (JSON list of {from_status, to_status}
    transition records) so monitoring history uses one vocabulary.

The audit trail's free-form detail JSON is deliberately NOT touched: it is an
immutable record of what was written at the time.

Revision ID: a1b2c3d4e501
Revises: 7260ed955c59
"""
import json

from alembic import op
import sqlalchemy as sa


revision = 'a1b2c3d4e501'
down_revision = '7260ed955c59'
branch_labels = None
depends_on = None

OLD_TO_NEW = {
    'Compliant': 'Language found',
    'Partially Compliant': 'Partially found',
    'Non-Compliant': 'Not found',
}
NEW_TO_OLD = {new: old for old, new in OLD_TO_NEW.items()}


def _rewrite_status_column(mapping):
    for src, dst in mapping.items():
        op.execute(sa.text('UPDATE control_results SET status = :dst WHERE status = :src')
                   .bindparams(src=src, dst=dst))


def _rewrite_flipped_json(mapping):
    bind = op.get_bind()
    rows = bind.execute(sa.text(
        'SELECT id, controls_flipped FROM policy_watch_runs WHERE controls_flipped IS NOT NULL'
    )).fetchall()
    for run_id, raw in rows:
        data = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
        if not isinstance(data, list):
            continue
        changed = False
        for entry in data:
            if not isinstance(entry, dict):
                continue
            for key in ('from_status', 'to_status', 'status'):
                if entry.get(key) in mapping:
                    entry[key] = mapping[entry[key]]
                    changed = True
        if changed:
            bind.execute(sa.text('UPDATE policy_watch_runs SET controls_flipped = :v WHERE id = :id')
                         .bindparams(v=json.dumps(data), id=run_id))


def upgrade():
    _rewrite_status_column(OLD_TO_NEW)
    _rewrite_flipped_json(OLD_TO_NEW)


def downgrade():
    _rewrite_status_column(NEW_TO_OLD)
    _rewrite_flipped_json(NEW_TO_OLD)
