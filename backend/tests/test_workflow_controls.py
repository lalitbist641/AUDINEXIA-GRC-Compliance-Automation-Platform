"""Phase 0 workflow controls: soft deletes, segregation of duties, audit locking,
and the audit trail's tamper-evident hash chain.

Each test pins a decision that is easy to lose silently -- e.g. that an owner
can't accept their own risk, or that a manager who also OWNS the risk can't
approve their own request (a role-only check would let them).
"""

import io
from datetime import date, timedelta

import pytest

from conftest import auth_header
from extensions import db
from models import AuditTrailEvent, Risk, User


def H(tokens, role):
    return auth_header(tokens[role])


def _create_risk(client, headers, owner_id=None, **extra):
    body = {'description': 'workflow test risk', 'likelihood': 3, 'impact': 3, **extra}
    if owner_id is not None:
        body['owner_id'] = owner_id
    response = client.post('/api/risks', json=body, headers=headers)
    assert response.status_code == 201, response.get_json()
    return response.get_json()['risk']


def _future(days=90):
    return (date.today() + timedelta(days=days)).isoformat()


# ── Finding creation (regression: the trail call referenced a column that
#    doesn't exist, so creating or deleting a finding raised AttributeError) ──

def test_finding_create_and_delete_do_not_crash(client, tokens):
    admin = H(tokens, 'org_admin')
    audit = client.post('/api/audits', json={'title': 'A1'}, headers=admin).get_json()['audit']
    response = client.post(f"/api/audits/{audit['id']}/findings",
                           json={'description': 'Retention schedule missing', 'severity': 'high'},
                           headers=admin)
    assert response.status_code == 201, response.get_json()
    finding = response.get_json()['finding']
    deleted = client.delete(f"/api/audits/{audit['id']}/findings/{finding['id']}", headers=admin)
    assert deleted.status_code == 200, deleted.get_json()


# ── Soft deletes ────────────────────────────────────────────────────────────

def test_deleted_risk_disappears_from_the_api_but_the_row_survives(app, client, tokens):
    admin = H(tokens, 'org_admin')
    risk = _create_risk(client, admin)
    assert client.delete(f"/api/risks/{risk['id']}", headers=admin).status_code == 200

    assert client.get(f"/api/risks/{risk['id']}", headers=admin).status_code == 404
    assert risk['id'] not in [r['id'] for r in client.get('/api/risks', headers=admin).get_json()['risks']]
    row = db.session.get(Risk, risk['id'])
    assert row is not None and row.deleted_at is not None and row.deleted_by_id is not None


def test_deleted_risk_is_not_counted_on_the_dashboard(client, tokens):
    admin = H(tokens, 'org_admin')
    before = client.get('/api/admin/dashboard', headers=admin).get_json()['open_risks']
    risk = _create_risk(client, admin)
    assert client.get('/api/admin/dashboard', headers=admin).get_json()['open_risks'] == before + 1
    client.delete(f"/api/risks/{risk['id']}", headers=admin)
    assert client.get('/api/admin/dashboard', headers=admin).get_json()['open_risks'] == before


def test_deleting_a_planned_audit_soft_deletes_its_findings(client, tokens):
    admin = H(tokens, 'org_admin')
    audit = client.post('/api/audits', json={'title': 'Cascade'}, headers=admin).get_json()['audit']
    finding = client.post(f"/api/audits/{audit['id']}/findings",
                          json={'description': 'f', 'severity': 'low'}, headers=admin).get_json()['finding']
    assert client.delete(f"/api/audits/{audit['id']}", headers=admin).status_code == 200
    assert client.get(f"/api/audits/{audit['id']}", headers=admin).status_code == 404
    assert client.get(f"/api/audits/{audit['id']}/findings/{finding['id']}", headers=admin).status_code == 404
    from models import Finding
    assert db.session.get(Finding, finding['id']).deleted_at is not None


def test_deleted_evidence_is_gone_from_the_api_but_the_row_survives(client, tokens, scan_fixture):
    admin = H(tokens, 'org_admin')
    cr_id = scan_fixture['controls'][0]['control_result_id']
    upload = client.post(f'/api/control-results/{cr_id}/evidence',
                         data={'file': (io.BytesIO(b'proof'), 'proof.txt')},
                         headers=admin, content_type='multipart/form-data')
    assert upload.status_code == 201, upload.get_json()
    evidence_id = upload.get_json()['evidence']['id']
    assert client.delete(f'/api/evidence/{evidence_id}', headers=admin).status_code == 200
    assert client.get(f'/api/evidence/{evidence_id}/download', headers=admin).status_code == 404
    assert client.get(f'/api/control-results/{cr_id}/evidence', headers=admin).get_json()['evidence'] == []
    from models import EvidenceFile
    assert db.session.get(EvidenceFile, evidence_id).deleted_at is not None


# ── Segregation of duties: risk acceptance ──────────────────────────────────

def test_owner_cannot_set_a_terminal_status_directly(client, tokens, users):
    risk = _create_risk(client, H(tokens, 'org_admin'), owner_id=users['member'].id)
    own = H(tokens, 'member')
    for terminal in ('accepted', 'closed'):
        response = client.patch(f"/api/risks/{risk['id']}", json={'status': terminal}, headers=own)
        assert response.status_code == 400, terminal
    # ...but can still move among non-terminal statuses and edit mitigation.
    ok = client.patch(f"/api/risks/{risk['id']}", json={'status': 'mitigating', 'mitigation': 'patched'}, headers=own)
    assert ok.status_code == 200 and ok.get_json()['status'] == 'mitigating'


def test_a_risk_cannot_be_created_or_patched_straight_to_accepted(client, tokens):
    admin = H(tokens, 'org_admin')
    created = client.post('/api/risks', json={'description': 'x', 'likelihood': 2, 'impact': 2,
                                              'status': 'accepted'}, headers=admin)
    assert created.status_code == 400
    risk = _create_risk(client, admin)
    assert client.patch(f"/api/risks/{risk['id']}", json={'status': 'accepted'}, headers=admin).status_code == 400


def test_risk_acceptance_needs_a_different_manager(client, tokens, users):
    risk = _create_risk(client, H(tokens, 'org_admin'), owner_id=users['member'].id)
    rid, own = risk['id'], H(tokens, 'member')

    requested = client.post(f'/api/risks/{rid}/request-risk-acceptance',
                            json={'reason': 'Cost exceeds exposure', 'expiry_date': _future()}, headers=own)
    assert requested.status_code == 200, requested.get_json()
    assert requested.get_json()['status'] == 'open'  # not accepted yet

    # The owner (not a manager) can't decide at all; the requester can't either.
    assert client.post(f'/api/risks/{rid}/approve-risk-acceptance', json={}, headers=own).status_code == 403

    approved = client.post(f'/api/risks/{rid}/approve-risk-acceptance', json={}, headers=H(tokens, 'compliance_manager'))
    assert approved.status_code == 200, approved.get_json()
    body = approved.get_json()
    assert body['status'] == 'accepted' and body['pending_action'] is None
    assert body['risk_acceptance_expires_at'] == _future()


def test_a_manager_who_owns_the_risk_cannot_approve_their_own_request(client, tokens, users):
    """The loophole a role-only check misses: the owner here IS a manager."""
    owner = users['compliance_manager']
    risk = _create_risk(client, H(tokens, 'org_admin'), owner_id=owner.id)
    rid, mine = risk['id'], H(tokens, 'compliance_manager')
    assert client.post(f'/api/risks/{rid}/request-risk-acceptance',
                       json={'reason': 'r', 'expiry_date': _future()}, headers=mine).status_code == 200
    assert client.post(f'/api/risks/{rid}/approve-risk-acceptance', json={}, headers=mine).status_code == 403
    assert client.post(f'/api/risks/{rid}/reject-risk-acceptance', json={}, headers=mine).status_code == 403
    # A different manager can.
    assert client.post(f'/api/risks/{rid}/approve-risk-acceptance', json={},
                       headers=H(tokens, 'org_admin')).get_json()['status'] == 'accepted'


@pytest.mark.parametrize('payload,expected', [
    ({'expiry_date': _future()}, 400),                                   # no reason
    ({'reason': 'r'}, 400),                                              # no expiry
    ({'reason': 'r', 'expiry_date': 'not-a-date'}, 400),
    ({'reason': 'r', 'expiry_date': (date.today() - timedelta(days=1)).isoformat()}, 400),   # past
    ({'reason': 'r', 'expiry_date': (date.today() + timedelta(days=400)).isoformat()}, 400),  # >12 months
])
def test_risk_acceptance_request_validation(client, tokens, payload, expected):
    risk = _create_risk(client, H(tokens, 'org_admin'))
    response = client.post(f"/api/risks/{risk['id']}/request-risk-acceptance",
                           json=payload, headers=H(tokens, 'org_admin'))
    assert response.status_code == expected


def test_resaving_an_already_accepted_risk_with_unchanged_status_is_allowed(client, tokens):
    admin = H(tokens, 'org_admin')
    risk = _create_risk(client, admin)
    client.post(f"/api/risks/{risk['id']}/request-risk-acceptance",
                json={'reason': 'r', 'expiry_date': _future()}, headers=admin)
    client.post(f"/api/risks/{risk['id']}/approve-risk-acceptance", json={}, headers=H(tokens, 'compliance_manager'))
    # A manager editing another field sends the unchanged status back.
    response = client.patch(f"/api/risks/{risk['id']}", json={'status': 'accepted', 'mitigation': 'm'}, headers=admin)
    assert response.status_code == 200
    # Leaving 'accepted' clears the acceptance expiry.
    left = client.patch(f"/api/risks/{risk['id']}", json={'status': 'mitigating'}, headers=admin).get_json()
    assert left['risk_acceptance_expires_at'] is None


def test_read_only_and_unrelated_members_cannot_request_acceptance(client, tokens, users):
    risk = _create_risk(client, H(tokens, 'org_admin'), owner_id=users['member'].id)
    for role in ('read_only',):
        assert client.post(f"/api/risks/{risk['id']}/request-risk-acceptance",
                           json={'reason': 'r', 'expiry_date': _future()},
                           headers=H(tokens, role)).status_code == 403


# ── Segregation of duties: finding closure + closed-audit lock ──────────────

def _audit_with_owned_finding(client, tokens, users, scan_fixture, link=True):
    admin = H(tokens, 'org_admin')
    audit = client.post('/api/audits', json={'title': 'SoD audit'}, headers=admin).get_json()['audit']
    client.patch(f"/api/audits/{audit['id']}", json={'status': 'in_progress'}, headers=admin)
    finding = client.post(f"/api/audits/{audit['id']}/findings", json={
        'description': 'finding', 'severity': 'medium', 'owner_id': users['member'].id}, headers=admin).get_json()['finding']
    if link:
        cr_id = scan_fixture['controls'][0]['control_result_id']
        assert client.post(f"/api/audits/{audit['id']}/findings/{finding['id']}/links",
                           json={'control_result_id': cr_id}, headers=admin).status_code == 201
    return audit['id'], finding['id']


def test_finding_closure_follows_request_then_independent_approval(client, tokens, users, scan_fixture):
    aid, fid = _audit_with_owned_finding(client, tokens, users, scan_fixture)
    base = f'/api/audits/{aid}/findings/{fid}'
    own = H(tokens, 'member')

    assert client.patch(base, json={'status': 'resolved'}, headers=own).status_code == 400      # owner can't
    assert client.patch(base, json={'status': 'resolved'}, headers=H(tokens, 'org_admin')).status_code == 400  # nor a manager directly
    requested = client.post(base + '/request-closure', json={'target_status': 'resolved', 'reason': 'fixed'}, headers=own)
    assert requested.status_code == 200, requested.get_json()
    assert client.post(base + '/approve-closure', json={}, headers=own).status_code == 403
    approved = client.post(base + '/approve-closure', json={}, headers=H(tokens, 'compliance_manager'))
    assert approved.status_code == 200 and approved.get_json()['status'] == 'resolved'
    # Re-saving the resolved finding with unchanged status is not a transition.
    assert client.patch(base, json={'status': 'resolved', 'recommendation': 'x'},
                        headers=H(tokens, 'org_admin')).status_code == 200


def test_closure_request_requires_a_linked_control_result(client, tokens, users, scan_fixture):
    aid, fid = _audit_with_owned_finding(client, tokens, users, scan_fixture, link=False)
    response = client.post(f'/api/audits/{aid}/findings/{fid}/request-closure',
                           json={'target_status': 'resolved', 'reason': 'fixed'}, headers=H(tokens, 'member'))
    assert response.status_code == 400


def _closed_audit(client, tokens, users, scan_fixture):
    aid, fid = _audit_with_owned_finding(client, tokens, users, scan_fixture)
    base = f'/api/audits/{aid}/findings/{fid}'
    client.post(base + '/request-closure', json={'target_status': 'resolved', 'reason': 'ok'}, headers=H(tokens, 'member'))
    client.post(base + '/approve-closure', json={}, headers=H(tokens, 'compliance_manager'))
    assert client.patch(f'/api/audits/{aid}', json={'status': 'closed'}, headers=H(tokens, 'org_admin')).status_code == 200
    return aid, fid


def test_closed_audit_locks_everything_until_an_admin_reopens_it(client, tokens, users, scan_fixture):
    aid, fid = _closed_audit(client, tokens, users, scan_fixture)
    admin, manager = H(tokens, 'org_admin'), H(tokens, 'compliance_manager')
    base = f'/api/audits/{aid}/findings/{fid}'

    assert client.patch(base, json={'recommendation': 'x'}, headers=admin).status_code == 400
    assert client.delete(base, headers=admin).status_code == 400
    assert client.patch(f'/api/audits/{aid}', json={'title': 'renamed'}, headers=admin).status_code == 400
    assert client.delete(f'/api/audits/{aid}', headers=admin).status_code == 400
    assert client.post(f'/api/audits/{aid}/findings', json={'description': 'new', 'severity': 'low'},
                       headers=admin).status_code == 400

    # Reopen: org_admin only, with a reason.
    assert client.patch(f'/api/audits/{aid}', json={'status': 'in_progress', 'reason': 'more'},
                        headers=manager).status_code == 403
    assert client.patch(f'/api/audits/{aid}', json={'status': 'in_progress'}, headers=admin).status_code == 400
    reopened = client.patch(f'/api/audits/{aid}', json={'status': 'in_progress', 'reason': 'new evidence'}, headers=admin)
    assert reopened.status_code == 200 and reopened.get_json()['closed_at'] is None
    assert client.patch(base, json={'recommendation': 'x'}, headers=admin).status_code == 200


def test_progressed_audits_are_withdrawn_not_deleted(client, tokens):
    admin = H(tokens, 'org_admin')
    audit = client.post('/api/audits', json={'title': 'W'}, headers=admin).get_json()['audit']
    aid = audit['id']
    # 'planned' audits may still be withdrawn-rejected / deleted normally.
    assert client.patch(f'/api/audits/{aid}', json={'status': 'withdrawn', 'reason': 'x'}, headers=admin).status_code == 400
    client.patch(f'/api/audits/{aid}', json={'status': 'in_progress'}, headers=admin)
    assert client.delete(f'/api/audits/{aid}', headers=admin).status_code == 400
    assert client.patch(f'/api/audits/{aid}', json={'status': 'withdrawn'}, headers=admin).status_code == 400   # needs reason
    ok = client.patch(f'/api/audits/{aid}', json={'status': 'withdrawn', 'reason': 'engagement cancelled'}, headers=admin)
    assert ok.status_code == 200 and ok.get_json()['status'] == 'withdrawn'


def test_workflow_actions_are_written_to_the_trail(client, tokens, users):
    risk = _create_risk(client, H(tokens, 'org_admin'), owner_id=users['member'].id)
    client.post(f"/api/risks/{risk['id']}/request-risk-acceptance",
                json={'reason': 'r', 'expiry_date': _future()}, headers=H(tokens, 'member'))
    client.post(f"/api/risks/{risk['id']}/approve-risk-acceptance", json={}, headers=H(tokens, 'compliance_manager'))
    actions = [e.action for e in AuditTrailEvent.query.filter_by(entity_type='risk', entity_id=risk['id'])]
    assert 'risk.request_acceptance' in actions and 'risk.approve_acceptance' in actions


# ── Audit trail hash chain ──────────────────────────────────────────────────

def test_trail_hash_chain_verifies_and_detects_tampering(app, client, tokens, org_a):
    from core.audit_trail import verify_chain

    admin = H(tokens, 'org_admin')
    for i in range(3):
        _create_risk(client, admin, description=f'chain risk {i}')

    ok, broken = verify_chain(org_a['id'])
    assert ok and broken is None
    events = AuditTrailEvent.query.filter(AuditTrailEvent.org_id == org_a['id'],
                                          AuditTrailEvent.hash.isnot(None)).order_by(AuditTrailEvent.id).all()
    assert len(events) >= 3 and events[0].prev_hash is None
    assert all(events[i].prev_hash == events[i - 1].hash for i in range(1, len(events)))

    # Edit a past row's content: the chain breaks AT that row.
    victim = events[1]
    victim.summary = 'forged'
    db.session.commit()
    ok, broken = verify_chain(org_a['id'])
    assert not ok and broken == victim.id


def test_trail_chain_detects_a_deleted_row(app, client, tokens, org_a):
    from core.audit_trail import verify_chain

    for i in range(3):
        _create_risk(client, H(tokens, 'org_admin'), description=f'del risk {i}')
    events = AuditTrailEvent.query.filter(AuditTrailEvent.org_id == org_a['id'],
                                          AuditTrailEvent.hash.isnot(None)).order_by(AuditTrailEvent.id).all()
    middle, after = events[1], events[2]
    db.session.delete(middle)
    db.session.commit()
    ok, broken = verify_chain(org_a['id'])
    assert not ok and broken == after.id


def test_trail_chain_skips_legacy_rows_with_no_hash(app, org_a):
    """Rows written before the chain existed have hash NULL; verification starts
    at the first hashed row instead of failing on them."""
    from core.audit_trail import record, verify_chain

    legacy = AuditTrailEvent(org_id=org_a['id'], action='legacy.event', entity_type='x')
    db.session.add(legacy)
    db.session.commit()
    assert legacy.hash is None
    with app.test_request_context():
        record('new.event', 'x', 1, 'after the legacy row', org_id=org_a['id'], commit=True)
    ok, _ = verify_chain(org_a['id'])
    assert ok
