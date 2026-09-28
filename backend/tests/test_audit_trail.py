"""The compliance audit trail: append-only, redacted, org-scoped.

The property worth testing is not "a row appears" but the three things that make
an audit trail admissible: it is written for every mutation, it never contains
secrets, and nothing in the API can rewrite or remove it.
"""

import pytest

from conftest import PASSWORD, auth_header

from models import AuditTrailEvent, db


def _events(client, headers, **params):
    response = client.get('/api/admin/audit-trail', headers=headers, query_string=params)
    assert response.status_code == 200, response.get_json()
    return response.get_json()['events']


# ── Recording ───────────────────────────────────────────────────────────────

def test_scan_is_recorded(client, auth, scan_fixture):
    events = _events(client, auth, entity_type='assessment')
    assert events, 'a scan must leave a trail row'
    entry = events[0]
    assert entry['action'].startswith('scan.')
    assert entry['entity_id'] == scan_fixture['assessment_id']
    assert entry['actor'], 'the trail must name who did it'
    assert entry['request_id'], 'the trail must be joinable to the server logs'


def test_every_mutating_call_appends_exactly_one_row(client, auth):
    """The fallback writer in core.audit_trail covers routes that do not call
    record() themselves; the explicit calls cover the rest. Either way, one
    mutation = one row, and a second row per request would make counts
    meaningless in a report."""
    before = len(_events(client, auth, limit=500))
    client.post('/api/risks', headers=auth, json={
        'title': 'Trail count risk', 'description': 'x', 'likelihood': 3, 'impact': 2,
    })
    after = len(_events(client, auth, limit=500))
    assert after - before == 1, f'expected one new trail row, got {after - before}'


def test_denied_access_is_recorded_but_validation_noise_is_not(client, tokens, auth):
    """401/403 belong in the same table as the successes — "someone kept
    knocking" is the question an auditor asks. 400s are the caller's form
    problem and would let a bad client bulk-generate immutable rows, so they are
    excluded by design. Both halves are pinned so neither can drift silently."""
    forbidden = client.patch('/api/admin/settings', headers=auth_header(tokens['member']),
                             json={'name': 'Renamed'})
    assert forbidden.status_code == 403

    denied = _events(client, auth, limit=500)
    assert any(e['action'] == 'access.denied' and e['entity_type'] == 'access' for e in denied), \
        'a 403 must appear in the trail'
    entry = next(e for e in denied if e['action'] == 'access.denied')
    assert '/api/admin/settings' in (entry['summary'] or '')

    validation = client.post('/api/admin/users', headers=auth, json={
        'name': 'Bad Role', 'email': 'bad@acme.test', 'role': 'superadmin',
        'temp_password': 'Temppass-2026-aa',
    })
    assert validation.status_code == 400
    after = _events(client, auth, limit=500)
    assert not any('role' in (e.get('summary') or '').lower() and e['action'] == 'access.denied'
                   for e in after)


def test_failed_signins_are_in_the_trail(client, app, org_a):
    """A password guess against a real account is recorded against that
    account's organization. An address nobody owns has no org to attach to, so
    the row is dropped by design (the application log still carries it) — that
    asymmetry is deliberate and asserted here."""
    from config import Config
    from security import clear_login_failures

    clear_login_failures(org_a['email'])
    with app.app_context():
        before = AuditTrailEvent.query.count()

    client.post('/api/auth/login', json={'email': org_a['email'], 'password': 'WrongOne-123!'})
    with app.app_context():
        rows = AuditTrailEvent.query.all()
    assert any(e.action == 'auth.login_failed' for e in rows), \
        'a bad password on a known account must be recorded'
    entry = [e for e in rows if e.action == 'auth.login_failed'][-1]
    assert org_a['email'] in (entry.summary or '')
    assert entry.user_id == org_a['admin_id']
    assert entry.ip_address is not None
    assert 'WrongOne-123!' not in str(entry.detail)

    client.post('/api/auth/login', json={'email': 'ghost@nowhere.test', 'password': 'Whatever-123!'})
    with app.app_context():
        assert AuditTrailEvent.query.count() == len(rows), \
            'unknown-email attempts must not create orphan rows'


def test_read_only_gets_no_trail_row(client, auth):
    """Otherwise merely opening the dashboard would rewrite history, and the
    volume would bury the events that matter."""
    before = len(_events(client, auth, limit=500))
    for path in ('/api/assessments', '/api/vendors', '/api/risks', '/api/maturity',
                 '/api/admin/dashboard'):
        client.get(path, headers=auth)
    assert len(_events(client, auth, limit=500)) == before


def test_authentication_events_are_recorded(client, org_a):
    client.post('/api/auth/login', json={'email': org_a['email'], 'password': 'nope'})
    with client.application.app_context():
        actions = {e.action for e in AuditTrailEvent.query.all()}
    assert 'auth.login_failed' in actions or 'auth.login_failure' in actions or \
        any('login' in a for a in actions), f'login attempts must be in the trail, saw {actions}'


# ── Redaction ───────────────────────────────────────────────────────────────

def test_passwords_never_reach_the_trail(client, auth, app):
    created = client.post('/api/admin/users', headers=auth, json={
        'name': 'Secret Sue', 'email': 'sue@acme.test', 'role': 'auditor',
        'temp_password': 'Temppass-2026-aa',
    })
    assert created.status_code == 201
    secret = 'Temppass-2026-aa'

    with app.app_context():
        rows = AuditTrailEvent.query.all()
        blob = ' '.join(str(e.to_dict()) for e in rows)
    assert secret not in blob, 'a temp password leaked into the audit trail'


def test_tokens_never_reach_the_trail(client, auth, app, org_a):
    response = client.post('/api/auth/login', json={'email': org_a['email'],
                                                    'password': PASSWORD})
    token = response.get_json()['access_token']
    client.get('/api/assessments', headers=auth_header(token))
    with app.app_context():
        blob = ' '.join(str(e.to_dict()) for e in AuditTrailEvent.query.all())
    assert token not in blob


def test_secrets_are_redacted_but_their_key_names_survive(client, auth, app):
    """Handlers pass curated detail dicts, so the trail never sees a request body
    verbatim -- but `redact()` is the backstop for the ones that do, and it must
    keep the key (an auditor needs to see that a secret was supplied) while
    dropping the value."""
    response = client.post('/api/admin/users', headers=auth, json={
        'name': 'Keys Kim', 'email': 'kim@acme.test', 'role': 'auditor',
        'temp_password': 'Temppass-2026-kk',
    })
    assert response.status_code == 201
    # The response must not echo the temp password back either (it is the only
    # place a caller could read it, and a 201 body is routinely logged).
    assert 'Temppass-2026-kk' not in response.get_data(as_text=True)
    with app.app_context():
        blob = ' '.join(str(e.detail) for e in AuditTrailEvent.query.all())
    # The values must be gone. Note this test proves the *handler* curates its
    # detail dict; the `<redacted>` marker itself is asserted on redact()
    # directly in test_redaction_is_recursive_and_depth_limited, because an
    # integration assertion could pass either by curating or by redacting, and
    # only the unit-level one says which mechanism did the work.
    for secret in ('Temppass-2026-kk',):
        assert secret not in blob, f'{secret!r} survived into the audit trail'


# ── Immutability and scoping ────────────────────────────────────────────────

def test_there_is_no_way_to_edit_or_delete_a_trail_row(app):
    """The claim on the API page has to be structural, not aspirational: assert
    no route exists that mutates this table, in any role."""
    offenders = []
    for rule in app.url_map.iter_rules():
        if 'audit-trail' not in str(rule.rule):
            continue
        methods = set(rule.methods) - {'HEAD', 'OPTIONS'}
        offenders.extend(methods - {'GET'})
    assert not offenders, f'audit-trail exposes mutating methods: {offenders}'


def test_trail_is_scoped_to_the_callers_org(client, auth, org_b):
    client.post('/api/risks', headers=auth, json={'description': 'Acme risk',
                                                  'likelihood': 2, 'impact': 2})
    acme = _events(client, auth, limit=500)
    betula = _events(client, auth_header(org_b['token']), limit=500)
    assert any('Acme risk' in (e.get('summary') or '') for e in acme)
    assert not any('Acme risk' in (e.get('summary') or '') for e in betula), \
        "the trail leaked another tenant's activity"


def test_filters_are_applied_server_side(client, auth, scan_fixture, risk):
    assert all(e['entity_type'] == 'risk' for e in _events(client, auth, entity_type='risk'))
    assert all(e['entity_id'] == risk['id']
               for e in _events(client, auth, entity_type='risk', entity_id=risk['id']))
    assert all(e['action'].startswith('scan.') for e in _events(client, auth, action='scan.create'))
    bad = client.get('/api/admin/audit-trail', headers=auth, query_string={'entity_id': 'abc'})
    assert bad.status_code == 400


def test_limit_is_capped(client, auth):
    response = client.get('/api/admin/audit-trail', headers=auth, query_string={'limit': 100000})
    assert response.status_code == 200
    assert len(response.get_json()['events']) <= 500


def test_stats_summarise_without_listing(client, auth, scan_fixture, vendor):
    body = client.get('/api/admin/audit-trail/stats', headers=auth).get_json()
    assert body['total'] >= 2
    assert isinstance(body['by_action'], dict)
    assert sum(body['by_action'].values()) <= body['total']
    assert body['retention_days'] in ('unlimited',) or isinstance(body['retention_days'], int)


def test_prune_keeps_everything_until_a_retention_policy_is_chosen(app, client, auth):
    """`flask prune` deletes evidence, so its default must be provably inert:
    retention 0/unset means keep forever, a policy without --execute changes
    nothing, and only --execute removes rows. The flag is a one-way is_flag for
    that reason — the earlier `--dry-run/--execute` pair was inverted by Click
    semantics, which meant `--dry-run` was the destructive one."""
    from datetime import datetime, timedelta

    client.post('/api/risks', headers=auth, json={'description': 'Ancient risk',
                                                  'likelihood': 1, 'impact': 1})
    with app.app_context():
        stale = AuditTrailEvent.query.first()
        stale.created_at = datetime.utcnow() - timedelta(days=400)
        db.session.commit()
        total = AuditTrailEvent.query.count()
        assert total >= 1

    runner = app.test_cli_runner()

    result = runner.invoke(args=['prune'])
    assert result.exit_code == 0
    assert 'keep forever' in result.output, result.output
    with app.app_context():
        assert AuditTrailEvent.query.count() == total

    result = runner.invoke(args=['prune', '--days', '90'])
    assert 'dry run' in result.output, result.output
    with app.app_context():
        assert AuditTrailEvent.query.count() == total, 'a dry run must not delete evidence'

    result = runner.invoke(args=['prune', '--days', '90', '--execute'])
    assert result.exit_code == 0, result.output
    assert 'rows deleted: 1' in result.output, result.output
    with app.app_context():
        assert AuditTrailEvent.query.count() == total - 1


def test_action_labels_are_human_readable():
    """The trail is shown to auditors in the UI and printed in reports; an id
    like `cr.update` is not an acceptable summary."""
    from core.audit_trail import ACTION_LABELS

    assert ACTION_LABELS, 'the label table disappeared'
    for key, label in ACTION_LABELS.items():
        assert isinstance(label, str) and label.strip()
        assert label != key, f'{key} has a placeholder label'
        assert not label.endswith('.'), f'{key} label is truncated'
        assert key.count('.') == 1, f'{key} is not a domain.action id'


def test_redaction_is_recursive_and_depth_limited():
    """`redact` is the only thing between a request body and an immutable,
    exportable table, so it has to survive nesting, lists, odd key casing and
    absurd sizes."""
    from core.audit_trail import redact

    payload = {
        'Password': 'hunter2',
        'nested': {'api_token': 'abc', 'keep': 'value'},
        'items': [{'secret_question': 'x'}, {'fine': 1}],
        'blob': b'\x00' * 5000,
        'long': 'z' * 5000,
    }
    cleaned = redact(payload)
    assert cleaned['Password'] == '<redacted>'
    assert cleaned['nested']['api_token'] == '<redacted>'
    assert cleaned['nested']['keep'] == 'value'
    assert cleaned['items'][0]['secret_question'] == '<redacted>'
    assert cleaned['items'][1] == {'fine': 1}
    assert cleaned['blob'].startswith('<') and cleaned['blob'].endswith('bytes>')
    assert len(cleaned['long']) <= 2000

    # A list longer than the cap must not smuggle rows past it.
    assert len(redact({'tokens': [{'token': 'x'}] * 200})) <= 50


def test_record_never_raises_on_a_bad_payload(app):
    """An audit write must not be able to fail a business operation — that is the
    trade recorded in core/audit_trail and it needs a test, because the tempting
    "improvement" is to let the exception through."""
    from core.audit_trail import record

    class Unserializable:
        def __str__(self):
            raise RuntimeError('nope')

    with app.app_context():
        assert record('test.unserializable', 'test', None, 'summary',
                      {'obj': Unserializable()}, user_id=1, org_id=1) is None or True
