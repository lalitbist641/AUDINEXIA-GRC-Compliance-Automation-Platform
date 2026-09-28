"""Role gates and tenant isolation.

Two properties are pinned here, and both are the kind that regress silently:

* The published role matrix matches the decorators on the routes. The spec the
  `/docs` page renders is derived from `__audinexia_roles__`, so if a handler's
  role list changes, the documentation changes with it and this test is the
  place where a human has to agree that the change was intended.
* No query path escapes `current_org_id()`. Cross-tenant access returns 404
  rather than 403 — a 403 would confirm the row exists in another tenant, which
  is itself a leak.
"""

import pytest

from conftest import auth_header

from models import ROLES


# Written out rather than derived from the code, on purpose: a test that reads
# the same decorator it is checking proves nothing. These are the intended
# rules; the loop turns any drift into a failure that a human has to agree to.
EXPECTED_GATES = {
    ('GET', '/api/assessments'): set(ROLES),
    ('POST', '/api/scan'): {'org_admin', 'compliance_manager', 'auditor', 'member'},
    ('POST', '/api/revise-policy'): {'org_admin', 'compliance_manager'},
    ('GET', '/api/admin/users'): {'org_admin', 'compliance_manager', 'auditor'},
    ('POST', '/api/admin/users'): {'org_admin'},
    ('PATCH', '/api/admin/users/<int:user_id>'): {'org_admin'},
    ('POST', '/api/admin/users/<int:user_id>/password'): {'org_admin'},
    ('PATCH', '/api/admin/settings'): {'org_admin'},
    ('GET', '/api/admin/audit-trail'): {'org_admin', 'compliance_manager', 'auditor'},
    ('POST', '/api/risks'): {'org_admin', 'compliance_manager', 'auditor'},
    ('DELETE', '/api/risks/<int:risk_id>'): {'org_admin', 'compliance_manager', 'auditor'},
    ('POST', '/api/vendors'): {'org_admin', 'compliance_manager'},
    ('DELETE', '/api/vendors/<int:vendor_id>'): {'org_admin'},
    ('POST', '/api/vendors/<int:vendor_id>/assessments'): {'org_admin', 'compliance_manager',
                                                            'auditor', 'member'},
    ('POST', '/api/monitoring/watches'): {'org_admin', 'compliance_manager'},
    ('DELETE', '/api/monitoring/watches/<int:watch_id>'): {'org_admin'},
    ('POST', '/api/monitoring/watches/<int:watch_id>/run'): {'org_admin', 'compliance_manager',
                                                             'auditor', 'member'},
    ('PATCH', '/api/maturity/<framework>'): {'org_admin', 'compliance_manager'},
    ('PATCH', '/api/control-results/<int:control_result_id>'): {'org_admin', 'compliance_manager',
                                                                 'auditor'},
    ('POST', '/api/control-results/<int:control_result_id>/evidence'): {'org_admin',
                                                                        'compliance_manager',
                                                                        'auditor', 'member'},
    ('DELETE', '/api/evidence/<int:evidence_id>'): {'org_admin', 'compliance_manager'},
}

def _roles_for(app, method, path):
    for rule in app.url_map.iter_rules():
        if str(rule.rule) == path and method in rule.methods:
            view = app.view_functions[rule.endpoint]
            return getattr(view, '__audinexia_roles__', None)
    raise AssertionError(f'no route for {method} {path}')


@pytest.mark.parametrize('method,path', sorted(EXPECTED_GATES))
def test_documented_role_matrix_matches_the_code(app, method, path):
    actual = _roles_for(app, method, path)
    assert actual is not None, f'{method} {path} has no @roles_required gate at all'
    assert set(actual) == EXPECTED_GATES[(method, path)], (
        f'{method} {path} allows {sorted(actual)}, expected '
        f'{sorted(EXPECTED_GATES[(method, path)])}')


def test_every_api_route_declares_only_real_roles(app):
    """A typo in a role name (`reveiwer`) does not fail closed — it fails open
    for nobody and 403s everyone, which reads as a broken deployment. Catching
    it at import time is much cheaper."""
    for rule in app.url_map.iter_rules():
        if not str(rule).startswith('/api/'):
            continue
        roles = getattr(app.view_functions[rule.endpoint], '__audinexia_roles__', None)
        if roles is None:
            continue
        unknown = set(roles) - set(ROLES)
        assert not unknown, f'{rule.rule} names unknown roles {sorted(unknown)}'


def test_read_only_role_can_read_everything_and_write_nothing(client, tokens):
    headers = auth_header(tokens['read_only'])
    for path in ('/api/assessments', '/api/risks', '/api/vendors', '/api/audits',
                 '/api/maturity', '/api/monitoring/watches', '/api/policy-documents',
                 '/api/admin/dashboard', '/api/admin/settings'):
        assert client.get(path, headers=headers).status_code == 200, path

    blocked = client.post('/api/risks', headers=headers, json={
        'title': 'x', 'description': 'y', 'likelihood': 3, 'impact': 3,
    })
    assert blocked.status_code == 403
    body = blocked.get_json()
    assert 'insufficient role' in body['error'].lower()
    assert body['your_role'] == 'read_only'
    # The refusal is self-documenting: it names what would be needed, which is
    # what makes a support ticket answerable.
    assert set(body['required_roles']) == {'org_admin', 'compliance_manager', 'auditor'}


def test_auditor_cannot_manage_vendors_or_settings(client, tokens):
    headers = auth_header(tokens['auditor'])
    assert client.post('/api/vendors', headers=headers, json={'name': 'V'}).status_code == 403
    assert client.patch('/api/admin/settings', headers=headers,
                        json={'name': 'Renamed'}).status_code == 403
    # ...but an auditor can run the checks that make them useful.
    assert client.get('/api/admin/audit-trail', headers=headers).status_code == 200
    assert client.get('/api/admin/users', headers=headers).status_code == 200


def test_manager_cannot_touch_administration(client, tokens):
    headers = auth_header(tokens['compliance_manager'])
    assert client.post('/api/admin/users', headers=headers,
                       json={'name': 'X', 'email': 'x@acme.test',
                             'temp_password': 'Temppass-2026-xx'}).status_code == 403
    assert client.patch('/api/admin/settings', headers=headers,
                        json={'default_policy_review_interval_days': 30}).status_code == 403
    assert client.post('/api/vendors', headers=headers, json={'name': 'Vendor One'}).status_code == 201


def test_member_can_read_and_scan_but_not_edit_the_register(client, tokens, app, org_a, users):
    member = users['member']
    headers = auth_header(tokens['member'])

    # Scoring a document and attaching evidence is contributor work.
    assert client.get('/api/assessments', headers=headers).status_code == 200
    # Changing the register of risks, or a control's review verdict, is not.
    assert client.post('/api/risks', headers=headers,
                       json={'title': 'x', 'description': 'y', 'likelihood': 1,
                             'impact': 1}).status_code == 403
    assert client.patch('/api/admin/settings', headers=headers,
                        json={'name': 'Nope'}).status_code == 403
    assert member.role == 'member'


# ── Ownership carve-out (the one place a non-manager may write) ──────────────

def test_assigned_member_may_update_only_status_and_mitigation_on_their_own_risk(
        client, auth, tokens, app, users):
    member = users['member']
    created = client.post('/api/risks', headers=auth, json={
        'title': 'Owner-carve-out risk', 'description': 'Assigned to a member.',
        'likelihood': 3, 'impact': 3, 'owner_id': member.id,
    })
    assert created.status_code == 201
    risk_id = created.get_json()['risk']['id']
    member_headers = auth_header(tokens['member'])

    allowed = client.patch(f'/api/risks/{risk_id}', headers=member_headers,
                           json={'status': 'mitigating', 'mitigation': 'Patch shipped in 4.2.'})
    assert allowed.status_code == 200
    assert allowed.get_json()['status'] == 'mitigating'
    assert allowed.get_json()['mitigation'].startswith('Patch shipped')

    refused = client.patch(f'/api/risks/{risk_id}', headers=member_headers,
                           json={'likelihood': 1, 'impact': 1})
    assert refused.status_code == 400
    assert 'only update' in refused.get_json()['error']

    # A different member owns nothing and gets nothing.
    other = client.patch(f'/api/risks/{risk_id}', headers=auth_header(tokens['read_only']),
                         json={'status': 'closed'})
    assert other.status_code == 403


def test_owner_carve_out_does_not_extend_to_other_risks(client, tokens, app, org_a):
    """The gate is per-row: being an owner somewhere must not become a global
    write permission."""
    orphan = client.post('/api/risks', headers=auth_header(tokens['org_admin']), json={
        'title': 'Unassigned risk', 'description': 'No owner.', 'likelihood': 2, 'impact': 2,
    }).get_json()['risk']
    response = client.patch(f"/api/risks/{orphan['id']}", headers=auth_header(tokens['member']),
                            json={'status': 'closed'})
    assert response.status_code == 403


# ── Tenant isolation ────────────────────────────────────────────────────────

@pytest.mark.parametrize('collection,member_path,body,envelope', [
    ('/api/vendors', '/api/vendors/{}', {'name': 'Tenant A vendor'}, 'vendor'),
    ('/api/risks', '/api/risks/{}', {'title': 'Tenant A risk', 'description': 'x',
                                     'likelihood': 3, 'impact': 3}, 'risk'),
    ('/api/audits', '/api/audits/{}', {'title': 'Tenant A audit',
                                      'audit_type': 'internal'}, 'audit'),
])
def test_other_tenants_rows_are_not_found(client, auth, org_b, collection, member_path,
                                          body, envelope):
    created = client.post(collection, headers=auth, json=body)
    assert created.status_code == 201, created.get_json()
    row_id = created.get_json()[envelope]['id']

    intruder = auth_header(org_b['token'])
    response = client.get(member_path.format(row_id), headers=intruder)
    assert response.status_code == 404, (
        f'{member_path} leaked a cross-tenant row as {response.status_code}')


def test_id_reuse_across_tenants_does_not_grant_access(client, auth, app, org_b, users):
    """org B must not be able to PATCH org A's risk by guessing its integer id."""
    created = client.post('/api/risks', headers=auth, json={
        'title': 'Belongs to Acme', 'description': 'x', 'likelihood': 4, 'impact': 4,
    })
    risk_id = created.get_json()['risk']['id']

    intruder = auth_header(org_b['token'])
    response = client.patch(f'/api/risks/{risk_id}', headers=intruder, json={'status': 'closed'})
    assert response.status_code == 404

    still_there = client.get(f'/api/risks/{risk_id}', headers=auth)
    assert still_there.status_code == 200
    assert still_there.get_json()['status'] != 'closed'


def test_lists_are_scoped_to_the_callers_org(client, auth, org_b):
    client.post('/api/vendors', headers=auth, json={'name': 'Acme-only vendor'})
    assert any(v['name'] == 'Acme-only vendor'
               for v in client.get('/api/vendors', headers=auth).get_json()['vendors'])
    betula = client.get('/api/vendors', headers=auth_header(org_b['token'])).get_json()['vendors']
    assert betula == [], f'org B saw {len(betula)} vendors, expected its own zero'


def test_org_b_scan_never_appears_in_org_a_history(client, auth, org_b, policy_dir):
    import io

    text = (policy_dir / 'compliant/Fully_Compliant_Policy.txt').read_bytes()
    inside = client.post('/api/scan', data={
        'file': (io.BytesIO(text), 'inside.txt'), 'framework': 'dpdpa',
    }, headers=auth_header(org_b['token']), content_type='multipart/form-data')
    assert inside.status_code == 200
    assert client.get('/api/assessments', headers=auth).get_json()['assessments'] == []
    assert len(client.get('/api/assessments',
                          headers=auth_header(org_b['token'])).get_json()['assessments']) == 1


def test_org_id_is_taken_from_the_token_not_the_body(client, auth, org_b):
    """A crafted `org_id` in a request must never move data between tenants."""
    response = client.post('/api/admin/users', headers=auth, json={
        'name': 'Sneaky', 'email': 'sneaky@acme.test', 'role': 'auditor',
        'temp_password': 'Temppass-2026-yy', 'org_id': org_b['id'],
    })
    assert response.status_code == 201
    from models import User

    with client.application.app_context():
        created = User.query.filter_by(email='sneaky@acme.test').first()
        assert created.org_id == org_a_id(client, auth)
        assert created.org_id != org_b['id']


def org_a_id(client, auth):
    return client.get('/api/auth/me', headers=auth).get_json()['organization']['id']


def test_cross_org_evidence_download_is_unavailable(client, auth, auth_b, app, scan_fixture):
    """`auth_b` is a second tenant's admin; the evidence file physically exists,
    so the only thing standing between them and another company's documents is
    the org filter on this route."""
    import io

    from models import ControlResult, db

    with app.app_context():
        cr_id = ControlResult.query.join(ControlResult.assessment).first().id
    upload = client.post(f'/api/control-results/{cr_id}/evidence', headers=auth, data={
        'file': (io.BytesIO(b'audit evidence'), 'evidence.txt'),
    }, content_type='multipart/form-data')
    assert upload.status_code == 201, upload.get_json()
    evidence_id = upload.get_json()['evidence']['id']

    assert client.get(f'/api/evidence/{evidence_id}/download', headers=auth_b).status_code == 404
    assert client.delete(f'/api/evidence/{evidence_id}', headers=auth_b).status_code == 404


@pytest.fixture
def auth_b(org_b):
    return auth_header(org_b['token'])
