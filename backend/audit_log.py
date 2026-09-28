import hashlib
import json
from datetime import datetime

from flask import request

from extensions import db
from models import AuditEvent


def _canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(',', ':'), default=str)


def record_audit_event(org_id, actor_id, action, entity_type, entity_id, changes=None, reason=None):
    """Appends one AuditEvent, chaining its hash to the previous event for
    this org. Call sites are explicit (each route that creates/updates/
    soft-deletes an audited entity calls this directly) rather than an
    automatic before_flush listener -- simpler to reason about and verify
    with no automated test suite to catch a subtle listener/flush-ordering
    bug. Does NOT commit -- callers add this to the same db.session.commit()
    as the entity change it's describing, so the event and the change it
    records land in the same transaction."""
    last = (
        AuditEvent.query.filter_by(org_id=org_id)
        .order_by(AuditEvent.id.desc())
        .first()
    )
    prev_hash = last.hash if last else None
    created_at = datetime.utcnow()
    actor_ip = request.remote_addr if request else None

    payload = {
        'org_id': org_id,
        'actor_id': actor_id,
        'actor_ip': actor_ip,
        'action': action,
        'entity_type': entity_type,
        'entity_id': entity_id,
        'changes': changes,
        'reason': reason,
        'created_at': created_at.isoformat(),
        'prev_hash': prev_hash,
    }
    event_hash = hashlib.sha256(_canonical(payload).encode('utf-8')).hexdigest()

    event = AuditEvent(
        org_id=org_id,
        actor_id=actor_id,
        actor_ip=actor_ip,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        changes=changes,
        reason=reason,
        created_at=created_at,
        prev_hash=prev_hash,
        hash=event_hash,
    )
    db.session.add(event)
    return event


def verify_chain(org_id):
    """Recomputes every event's hash from its own content + the previous
    event's hash and compares against the stored value. Returns (ok: bool,
    first_broken_event_id: int | None). Not wired to any route in Phase 0
    -- used for direct verification (see the Phase 0 plan's verification
    step 2) and available for a future admin/audit-log endpoint."""
    events = AuditEvent.query.filter_by(org_id=org_id).order_by(AuditEvent.id.asc()).all()
    prev_hash = None
    for event in events:
        if event.prev_hash != prev_hash:
            return False, event.id
        payload = {
            'org_id': event.org_id,
            'actor_id': event.actor_id,
            'actor_ip': event.actor_ip,
            'action': event.action,
            'entity_type': event.entity_type,
            'entity_id': event.entity_id,
            'changes': event.changes,
            'reason': event.reason,
            'created_at': event.created_at.isoformat(),
            'prev_hash': event.prev_hash,
        }
        recomputed = hashlib.sha256(_canonical(payload).encode('utf-8')).hexdigest()
        if recomputed != event.hash:
            return False, event.id
        prev_hash = event.hash
    return True, None
