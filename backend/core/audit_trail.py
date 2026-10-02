"""Audit-trail recording (report §12.1 "satisfying the basic auditability
expectation of any real compliance tool").

Design decisions, all deliberate:

* Explicit call from route handlers, not ORM event hooks. An audit record that
  matters carries intent ("compliance_manager overrode control score", "member
  deleted evidence") — that is only knowable at the route.
* `record()` never raises. A write-only trail that can take down a scan
  endpoint is worse than no trail; failures are logged and counted instead.
* The trail is append-only at the API level (list/read only, no update or
  delete route) and carries the org_id so every read is tenant-scoped like
  every other table here.
* Detail payloads store *what changed*, never secrets — see SENSITIVE_KEYS.
"""

import hashlib
import json
from datetime import datetime
from uuid import uuid4

from flask import current_app, g, has_request_context, request

from extensions import db
from models import AuditTrailEvent

SENSITIVE_KEYS = {'password', 'temp_password', 'new_password', 'password_hash',
                  'access_token', 'refresh_token', 'authorization', 'secret',
                  'token', 'api_key'}


def _safe_jwt_claims():
    """get_jwt() raises RuntimeError when no @jwt_required() ran in this
    request; a trail entry recorded from a public endpoint must still work."""
    try:
        from flask_jwt_extended import get_jwt

        return get_jwt() or {}
    except RuntimeError:
        return {}


def _safe_jwt_identity():
    try:
        from flask_jwt_extended import get_jwt_identity

        return get_jwt_identity()
    except RuntimeError:
        return None


def new_request_id():
    return uuid4().hex


def current_request_id():
    if has_request_context() and getattr(g, 'request_id', None):
        return g.request_id
    return None


def redact(payload):
    """Drop credential-shaped keys before anything reaches the trail.

    Simple and conservative: an unknown key containing 'token'/'secret' is
    dropped too. The trail is meant to record actions, not request bodies.
    """
    if payload is None:
        return None
    if isinstance(payload, (bytes, bytearray)):
        return f'<{len(payload)} bytes>'
    if isinstance(payload, str):
        return payload[:2000]
    if isinstance(payload, (int, float, bool)):
        return payload
    if isinstance(payload, dict):
        out = {}
        for key, value in payload.items():
            if any(bad in str(key).lower() for bad in SENSITIVE_KEYS):
                out[key] = '<redacted>'
            else:
                out[key] = redact(value)
        return out
    if isinstance(payload, (list, tuple)):
        return [redact(v) for v in list(payload)[:50]]
    return str(payload)[:500]


def _chain_hash(payload):
    """sha256 over a canonical JSON form of the event's own content + the previous
    event's hash. Canonical (sorted keys, no whitespace, str() for anything
    non-JSON) so verification recomputes exactly what was hashed at write time."""
    blob = json.dumps(payload, sort_keys=True, separators=(',', ':'), default=str)
    return hashlib.sha256(blob.encode('utf-8')).hexdigest()


def _event_payload(event, prev_hash):
    return {
        'org_id': event.org_id, 'user_id': event.user_id, 'action': event.action,
        'entity_type': event.entity_type, 'entity_id': event.entity_id,
        'summary': event.summary, 'detail': event.detail, 'ip_address': event.ip_address,
        'request_id': event.request_id, 'created_at': event.created_at.isoformat(),
        'prev_hash': prev_hash,
    }


def verify_chain(org_id):
    """Recompute every hashed event's hash and the prev_hash links for an org.

    Returns (ok, first_broken_event_id). Rows written before the chain existed
    (hash NULL) are skipped: the chain begins at the first hashed row. A tampered
    row (content edited), a deleted row (the next row's prev_hash no longer
    matches), or a reordered/forged row all surface as the first broken id.

    Limits, stated plainly: this detects alteration by someone who does NOT also
    recompute every later hash. An attacker with write access to the database who
    rewrites the whole tail of the chain defeats it -- real tamper-proofing needs
    the latest hash anchored somewhere the database user can't write (a WORM
    store, a separate service). Under concurrent writers for one org, two events
    can compute the same prev_hash; the lookup below takes a row lock where the
    database supports it (Postgres), which SQLite doesn't need (single writer)."""
    events = (AuditTrailEvent.query.filter(AuditTrailEvent.org_id == org_id,
                                           AuditTrailEvent.hash.isnot(None))
              .order_by(AuditTrailEvent.id.asc()).all())
    prev = None
    for event in events:
        if event.prev_hash != prev:
            return False, event.id
        if _chain_hash(_event_payload(event, event.prev_hash)) != event.hash:
            return False, event.id
        prev = event.hash
    return True, None


def record(action, entity_type, entity_id=None, summary=None, detail=None,
           user_id=None, org_id=None, commit=False):
    """Append one trail entry. Call inside a request context; the actor is read
    from the JWT claims so a handler cannot forget to attribute itself.

    Uses a SAVEPOINT (nested transaction) so a trail-insert failure cannot poison
    the caller's pending business transaction: the savepoint rolls back, the
    outer transaction still commits.

    `commit=True` is for callers with no following commit — which is exactly the
    after_request fallback writer, and the reason that flag exists. A savepoint
    commit only makes a row durable once the *outer* transaction commits; when
    record() is called after the handler has already committed, there is no outer
    commit left, and the entry was flushed and then silently rolled back at
    session teardown. Every trail row for an endpoint that relied on the fallback
    (risk register, audit findings, control reviews, evidence) disappeared
    without an error until that was fixed.
    """
    try:
        if (org_id is None or user_id is None) and has_request_context():
            # get_jwt()/get_jwt_identity() raise outside a @jwt_required
            # endpoint, and some recorded actions (login, register, a
            # background monitoring run) legitimately have no verified token.
            claims = _safe_jwt_claims()
            if org_id is None:
                org_id = claims.get('org_id')
            if user_id is None:
                identity = _safe_jwt_identity()
                user_id = int(identity) if identity else None

        if not org_id:
            # Nothing in this API writes cross-tenant; a trail row with no org
            # would be unreadable by everyone, so drop it loudly instead.
            current_app.logger.warning('audit trail entry dropped (no org_id): %s', action)
            return None

        event = AuditTrailEvent(
            org_id=org_id,
            user_id=user_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            summary=(summary or '')[:500] or None,
            detail=redact(detail) if detail is not None else None,
            ip_address=request.remote_addr if has_request_context() else None,
            request_id=current_request_id(),
            # Set explicitly (not the column default) so it's part of the hash.
            created_at=datetime.utcnow(),
        )
        nested = db.session.begin_nested()
        last_hash = (db.session.query(AuditTrailEvent.hash)
                     .filter(AuditTrailEvent.org_id == org_id, AuditTrailEvent.hash.isnot(None))
                     .order_by(AuditTrailEvent.id.desc()).with_for_update().limit(1).scalar())
        event.prev_hash = last_hash
        event.hash = _chain_hash(_event_payload(event, last_hash))
        db.session.add(event)
        db.session.flush()
        nested.commit()
        if commit:
            db.session.commit()
        # Tell the fallback writer (auto_record_mutation) that this request has
        # already been described properly, so the trail holds one row per
        # request rather than a rich one plus a generic duplicate.
        if has_request_context():
            g.audit_trail_written = True
        return event.id
    except Exception as exc:  # never fail the business operation over an audit write
        try:
            db.session.rollback()
        except Exception:
            pass
        current_app.logger.error('audit trail write failed (%s %s): %s', action, entity_type, exc)
        return None


ACTION_LABELS = {
    'assessment.delete': 'Deleted assessment',
    'control_result.update': 'Updated control review',
    'control_result.evidence_upload': 'Uploaded evidence',
    'evidence.delete': 'Deleted evidence file',
    'risk.create': 'Created risk',
    'risk.update': 'Updated risk',
    'risk.delete': 'Deleted risk',
    'risk.request_acceptance': 'Requested risk acceptance',
    'risk.approve_acceptance': 'Approved risk acceptance',
    'risk.reject_acceptance': 'Rejected risk acceptance',
    'risk.link': 'Linked control to risk',
    'risk.unlink': 'Unlinked control from risk',
    'audit.create': 'Created audit',
    'audit.update': 'Updated audit',
    'audit.delete': 'Deleted audit',
    'audit.reopen': 'Reopened a closed audit',
    'audit.withdraw': 'Withdrew audit',
    'finding.create': 'Created audit finding',
    'finding.update': 'Updated audit finding',
    'finding.delete': 'Deleted audit finding',
    'finding.request_closure': 'Requested finding closure',
    'finding.approve_closure': 'Approved finding closure',
    'finding.reject_closure': 'Rejected finding closure',
    'finding.link': 'Linked control to finding',
    'finding.unlink': 'Unlinked control from finding',
    'admin.user_create': 'Created user',
    'admin.user_update': 'Updated user',
    'admin.password_reset': 'Reset a user password',
    'auth.login': 'Signed in',
    'auth.login_failed': 'Failed sign-in attempt',
    'auth.login_locked': 'Account lockout engaged by repeated failed sign-ins',
    'auth.logout': 'Signed out',
    'auth.register': 'Registered organization',
    'auth.password_change': 'Changed own password',
    'auth.password_reset_requested': 'Requested a password reset link',
    'auth.password_reset': 'Reset password through an emailed link',
}


def auto_record_mutation(response):
    """Fallback trail writer for mutating API calls whose handler did not call
    record() itself.

    Why both mechanisms exist: a compliance tool's trail is only worth
    something if it is complete, and completeness cannot depend on every future
    endpoint author remembering a call. So the framework writes one line per
    successful mutation by default (method, endpoint, entity ids, status,
    actor, request id), and a handler replaces that with a richer, human
    readable entry by calling record() itself — at most one row per request
    either way, tracked on `g`.
    """
    from flask import g

    if not has_request_context():
        return response
    if getattr(g, 'audit_trail_written', False):
        return response
    if request.method not in ('POST', 'PATCH', 'PUT', 'DELETE'):
        return response
    if not request.path.startswith('/api/'):
        return response
    # Exports and downloads are reads in a POST wrapper; recording them would
    # bury the changes anyone auditing this organization actually cares about.
    if request.path.startswith(('/api/export-', '/api/auth/password-policy', '/api/evidence/')):
        return response
    # Successful mutations are the baseline. Denied ones are recorded too, but
    # only the two statuses that mean "access control said no" (401 unauthenticated,
    # 403 forbidden): an auditor asking "did anyone try to reach another tenant's
    # data, or keep using an account after deactivation?" needs the refusals in
    # the same table as the successes. Validation failures (400/422) are
    # deliberately excluded — they are noise from the caller's own form, they can
    # be generated in bulk, and they repeat user-supplied text back into an
    # immutable table, which is a log-injection surface nobody needs.
    if response.status_code >= 400 and response.status_code not in (401, 403):
        return response

    entity_id = None
    for value in request.view_args.values():
        if isinstance(value, int):
            entity_id = value
            break

    denied = response.status_code in (401, 403)
    record(
        action='access.denied' if denied else f'request.{request.method.lower()}',
        entity_type='access' if denied else 'endpoint',
        entity_id=entity_id,
        summary=(f'{request.method} {request.path} -> {response.status_code} '
                 f'({"denied" if denied else "ok"})'),
        detail={'endpoint': request.endpoint, 'status': response.status_code,
                'role': (_safe_jwt_claims() or {}).get('role') if denied else None,
                'path_params': {k: v for k, v in (request.view_args or {}).items()}},
        commit=True,
    )
    g.audit_trail_written = True
    return response


def to_json_rows(events):
    return [e.to_dict() for e in events]


def renderable(detail):
    """Helper for tests/debug: serialize a detail payload the same way the DB
    column would, so tests can assert on redaction without a round trip."""
    return json.dumps(redact(detail), sort_keys=True, default=str)
