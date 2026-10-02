"""The status-vocabulary data migration must rewrite persisted rows both ways.

Application code compares against the new strings, so a row left under the old
vocabulary would silently fall into the wrong branch (a "Compliant" control
treated as a gap, the remediation guard no longer recognising it).
"""

import importlib.util
import json
import os

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

MIGRATION = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         'migrations', 'versions', 'a1b2c3d4e501_phase0_honest_status_vocabulary.py')


def _load():
    spec = importlib.util.spec_from_file_location('status_migration', MIGRATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(engine, fn):
    import alembic.op as op_proxy

    with engine.begin() as conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            fn()


def _setup(engine):
    with engine.begin() as conn:
        conn.execute(sa.text('CREATE TABLE control_results (id INTEGER PRIMARY KEY, status TEXT)'))
        conn.execute(sa.text('CREATE TABLE policy_watch_runs (id INTEGER PRIMARY KEY, controls_flipped TEXT)'))
        for i, status in enumerate(['Compliant', 'Partially Compliant', 'Non-Compliant', 'Compliant'], 1):
            conn.execute(sa.text('INSERT INTO control_results VALUES (:i, :s)'), {'i': i, 's': status})
        flips = [{'control_id': 'A', 'from_status': 'Compliant', 'to_status': 'Non-Compliant'},
                 {'control_id': 'B', 'from_status': 'Partially Compliant', 'to_status': 'Compliant'}]
        conn.execute(sa.text('INSERT INTO policy_watch_runs VALUES (1, :j)'), {'j': json.dumps(flips)})
        conn.execute(sa.text('INSERT INTO policy_watch_runs VALUES (2, NULL)'))


def _statuses(engine):
    with engine.connect() as conn:
        return [r[0] for r in conn.execute(sa.text('SELECT status FROM control_results ORDER BY id'))]


def _flips(engine):
    with engine.connect() as conn:
        raw = conn.execute(sa.text('SELECT controls_flipped FROM policy_watch_runs WHERE id = 1')).scalar()
    return json.loads(raw)


def test_upgrade_and_downgrade_round_trip():
    migration = _load()
    engine = sa.create_engine('sqlite://')
    _setup(engine)

    _run(engine, migration.upgrade)
    assert _statuses(engine) == ['Language found', 'Partially found', 'Not found', 'Language found']
    flips = _flips(engine)
    assert flips[0]['from_status'] == 'Language found' and flips[0]['to_status'] == 'Not found'
    assert flips[1]['from_status'] == 'Partially found' and flips[1]['to_status'] == 'Language found'

    _run(engine, migration.downgrade)
    assert _statuses(engine) == ['Compliant', 'Partially Compliant', 'Non-Compliant', 'Compliant']
    assert _flips(engine)[0]['from_status'] == 'Compliant'


def test_upgrade_is_idempotent_for_rows_already_on_the_new_vocabulary():
    migration = _load()
    engine = sa.create_engine('sqlite://')
    _setup(engine)
    _run(engine, migration.upgrade)
    _run(engine, migration.upgrade)
    assert _statuses(engine) == ['Language found', 'Partially found', 'Not found', 'Language found']
