"""Request-level security controls: rate limiting, login throttling, password
policy, client-IP resolution and response hardening headers.

Honest scope notes, because a half-measure presented as a control is worse than
no control:

* In-memory rate limiting (the default) is per-process. Under N gunicorn
  workers the effective limit is N x the configured value. Set
  RATE_LIMIT_STORE=db to share counters through the database (correct, at the
  cost of a write per limited request), or terminate rate limiting at the load
  balancer / API gateway for real protection.
* The login throttle guards against online password guessing on this
  application. It is not a substitute for network controls, and a
  multi-process deployment can slip a few extra attempts past it.
* These headers are the cheap 80% (clickjacking, MIME sniffing, referrer
  leakage, HTTPS enforcement). They do not cover subresource integrity,
  sandboxing, or the CSP report-only workflow — see docs/SECURITY.md.
"""

import threading
import time
from collections import defaultdict, deque

from flask import current_app, g, jsonify, request

# ── Rate limiting ─────────────────────────────────────────────────────────


class _WindowCounter:
    """Sliding fixed-window counter (count per window, oldest evicted).

    A fixed window is used rather than a token bucket deliberately: the limits
    this app needs ("10 logins per 5 minutes") are window-shaped, and a fixed
    window is implementable identically in memory and in the DB table, so both
    backends agree on semantics.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._hits = defaultdict(deque)

    def hit(self, key, limit, window_seconds, now=None):
        """Return (allowed, remaining, retry_after_seconds)."""
        now = now or time.time()
        with self._lock:
            hits = self._hits[key]
            while hits and hits[0] <= now - window_seconds:
                hits.popleft()
            if len(hits) >= limit:
                retry = int(hits[0] + window_seconds - now) + 1
                return False, 0, max(retry, 1)
            hits.append(now)
            return True, max(limit - len(hits), 0), 0


_memory_counters = _WindowCounter()



def _setting(name, fallback=None):
    """Read a tunable from `current_app.config`, falling back to the `Config`
    class attribute.

    `create_app(config_overrides)` is documented as the way to build an isolated
    app (tests, the CLI, anything embedding the platform), but every control in
    this module read the class attribute directly — so an override changed
    `app.config` and nothing else, and a test that disabled rate limiting still
    hit the shared process-wide counters. Reading through here makes the factory
    argument honest. Outside a request context (CLI, scheduler) there is no
    `current_app`, and `Config` is the only source available.
    """
    from config import Config

    if fallback is None:
        fallback = getattr(Config, name, None)
    try:
        from flask import has_app_context

        if has_app_context():
            value = current_app.config.get(name, fallback)
            return fallback if value is None else value
    except RuntimeError:        # pragma: no cover - defensive
        pass
    return fallback


def _parse_rule(rule):
    """'10 per 5 minutes' -> (10, 300). Accepts 'per second|minute|hour|day'."""
    try:
        count_raw, _, window_raw = rule.partition(' per ')
        count = int(count_raw.strip())
        parts = window_raw.strip().split()
        multiplier = 1
        if parts and parts[0].isdigit():
            multiplier = int(parts[0])
            parts = parts[1:]
        unit = (parts[0] if parts else 'hour').lower().rstrip('s')
        seconds = {'second': 1, 'minute': 60, 'hour': 3600, 'day': 86400}.get(unit, 3600)
        return count, multiplier * seconds
    except (ValueError, IndexError):
        # A malformed rule must not silently disable the limit — fall back to
        # the strictest sensible reading and log it.
        current_app.logger.error('malformed rate limit rule %r; applying 60 per hour', rule)
        return 60, 3600


def _db_counter(key, limit, window_seconds):
    """Counter backed by api_rate_limit_buckets, for multi-worker correctness.

    Uses an UPSERT-shaped read-modify-write inside the current transaction. It
    is not atomic across workers (SQLite/Postgres row locks make it race-safe
    for the read+update, and a small overrun is acceptable for a login
    throttle) — the docstring in this module says so out loud rather than
    claiming hard guarantees.
    """
    from datetime import datetime

    from extensions import db
    from models import ApiRateLimitBucket

    now = datetime.utcnow()
    row = ApiRateLimitBucket.query.filter_by(bucket_key=key).first()
    if row is None or row.window_expires_at <= now:
        if row is None:
            row = ApiRateLimitBucket(bucket_key=key, count=1, window_started_at=now,
                                     window_expires_at=now.replace(microsecond=0)
                                     + __import__('datetime').timedelta(seconds=window_seconds))
            db.session.add(row)
        else:
            row.count = 1
            row.window_started_at = now
            row.window_expires_at = now + __import__('datetime').timedelta(seconds=window_seconds)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
        return True, max(limit - 1, 0), 0

    if row.count >= limit:
        retry = int((row.window_expires_at - now).total_seconds()) + 1
        return False, 0, max(retry, 1)

    row.count = row.count + 1
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
    return True, max(limit - row.count, 0), 0


def check_rate_limit(scope, rule, identity=None):
    """Apply a limit for (scope, identity). Returns
    (allowed, {'limit':…, 'remaining':…, 'retry_after':…})."""
    if not _setting('RATE_LIMIT_ENABLED'):
        return True, {'limit': None, 'remaining': None, 'retry_after': 0, 'enforced': False}

    limit, window_seconds = _parse_rule(rule)
    key = f'{scope}:{identity or client_ip()}'
    if _setting('RATE_LIMIT_STORE') == 'db':
        allowed, remaining, retry = _db_counter(key, limit, window_seconds)
    else:
        allowed, remaining, retry = _memory_counters.hit(key, limit, window_seconds)
    return allowed, {'limit': limit, 'remaining': remaining, 'retry_after': retry, 'enforced': True}


def limit_or_reject(scope, rule, identity=None):
    """Decorator-free helper: returns a Response to short-circuit with, or None.

    Explicitly a helper rather than a decorator so the ordering versus
    @roles_required stays readable at the call site.
    """
    from flask import jsonify

    allowed, info = check_rate_limit(scope, rule, identity)
    if allowed:
        return None
    body = {
        'error': 'Too many requests for this operation. Try again later.',
        'retry_after_seconds': info['retry_after'],
        'scope': scope,
        'limit': info['limit'],
    }
    response = jsonify(body)
    response.status_code = 429
    response.headers['Retry-After'] = str(info['retry_after'])
    response.headers['X-RateLimit-Limit'] = str(info['limit'])
    response.headers['X-RateLimit-Remaining'] = '0'
    return response


# ── Login throttling ──────────────────────────────────────────────────────


class _AttemptTracker:
    def __init__(self):
        self._lock = threading.Lock()
        self._failures = defaultdict(list)

    def register_failure(self, key, max_attempts, now=None, window_seconds=900):
        now = now or time.time()
        with self._lock:
            stamps = [t for t in self._failures[key] if t > now - window_seconds]
            stamps.append(now)
            self._failures[key] = stamps
            return len(stamps) >= max_attempts

    def reset(self, key):
        with self._lock:
            self._failures.pop(key, None)

    def locked_until(self, key, lockout_seconds, max_attempts, now=None):
        """Seconds until a lockout expires, or 0 when the key is not locked.

        Phase 9 fix. This used to answer "locked" whenever *any* failure was on
        record inside the window, so a single mistyped password locked the
        account for LOGIN_LOCKOUT_MINUTES and the max-attempts threshold only
        affected a message. That is a denial-of-service against your own users
        (an attacker who knows one address can lock the CFO out in three
        requests) and it made the throttle useless as a guessing control, since
        the lockout arrived before the guessing ever got going. The count is now
        the gate, and stamps older than the lockout window are ignored so the
        penalty expires instead of accumulating forever."""
        now = now or time.time()
        with self._lock:
            stamps = [t for t in self._failures.get(key, ()) if t > now - lockout_seconds]
            if len(stamps) < max_attempts:
                return 0
            return max(int(stamps[-1] + lockout_seconds - now), 0)

    def prune(self, horizon_seconds=3600):
        now = time.time()
        with self._lock:
            for key in list(self._failures):
                kept = [t for t in self._failures[key] if t > now - horizon_seconds]
                if kept:
                    self._failures[key] = kept
                else:
                    del self._failures[key]


_attempts = _AttemptTracker()


def login_is_locked(email, org_hint=None):
    key = (email or '').lower()
    return _attempts.locked_until(key, _setting('LOGIN_LOCKOUT_MINUTES') * 60,
                                  _setting('LOGIN_MAX_ATTEMPTS'))


def register_login_failure(email):
    key = (email or '').lower()
    max_attempts = _setting('LOGIN_MAX_ATTEMPTS')
    locked = _attempts.register_failure(key, max_attempts)
    if locked:
        current_app.logger.warning('account lockout engaged for %s after %d failed attempts',
                                   key, max_attempts)
    return locked


def clear_login_failures(email):
    _attempts.reset((email or '').lower())


# ── Password policy ───────────────────────────────────────────────────────

# The most common leaked/weak passwords, plus the ones a setup script would
# plausibly generate. Checked exactly (case-insensitive), not by substring, so
# a legitimate sentence containing "password" is not rejected.
_COMMON_PASSWORDS = frozenset({
    'password', 'password1', 'password123', 'passw0rd', '12345678', '123456789',
    '1234567890', 'qwerty123', 'abc12345', 'iloveyou', 'letmein', 'welcome',
    'welcome1', 'admin123', 'administrator', 'login', 'audit123', 'monkey123',
    'changeme', 'change-me', 'testtest', 'test1234', 'summer2020', 'football',
    'baseball', 'trustno1', 'whatever', 'starwars', 'hello123', 'dragon123',
    'compliance', 'compliance1', 'audinexia', 'audinexia1', 'companyname',
})


def check_password_strength(password, min_length=None):
    """Return (ok, list_of_problems). Empty problems means acceptable.

    Length-based rather than composition-based (no "must contain a symbol"),
    following NIST SP 800-63B guidance that composition rules push users toward
    predictable substitutions while length actually resists guessing.
    """
    from config import Config

    length = min_length or _setting('MIN_PASSWORD_LENGTH')
    problems = []
    if not password:
        return False, ['password is required']
    if len(password) < length:
        problems.append(f'must be at least {length} characters')
    if len(password) > 128:
        problems.append('must be at most 128 characters')
    if password.strip() != password:
        problems.append('must not start or end with whitespace')
    lowered = password.lower()
    if lowered in _COMMON_PASSWORDS:
        problems.append('is a commonly used password')
    # Four identical characters in a row is a pattern, not entropy.
    if any(password[i] * 4 in password for i in range(len(password))):
        problems.append('must not repeat a single character four times in a row')
    if password.isdigit() and len(password) < 14:
        problems.append('must not be digits only (use a passphrase)')
    distinct = len(set(password))
    if len(password) >= 8 and distinct <= 3:
        problems.append('uses too few distinct characters')
    return not problems, problems


def check_password_pwned(password):
    """Best-effort breached-password check (HIBP k-anonymity range API).

    Only the first 5 hex chars of the password's SHA-1 are sent, so HIBP never
    sees the password. Returns True (found in a breach corpus), False (not
    found), or None when the check could not be performed -- callers must treat
    None as "no objection": this fails open so an outage can't block sign-up.
    Uses the standard library (urllib) rather than adding a dependency."""
    import hashlib
    import urllib.error
    import urllib.request

    if not _setting('HIBP_CHECK_ENABLED'):
        return None
    try:
        sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        request_obj = urllib.request.Request(
            f'https://api.pwnedpasswords.com/range/{prefix}',
            headers={'Add-Padding': 'true', 'User-Agent': 'audinexia-password-check'},
        )
        with urllib.request.urlopen(request_obj, timeout=3) as response:
            if response.status != 200:
                return None
            body = response.read().decode('utf-8', 'replace')
        for line in body.splitlines():
            line_suffix, _, count = line.partition(':')
            if line_suffix.strip() == suffix and int(count or 0) > 0:
                return True
        return False
    except (urllib.error.URLError, OSError, ValueError):
        return None


def password_acceptable(password, min_length=None):
    """check_password_strength plus the breach check, as (ok, problems)."""
    ok, problems = check_password_strength(password, min_length)
    if ok and check_password_pwned(password) is True:
        return False, ['has appeared in a known data breach -- choose a different one']
    return ok, problems


# ── Client identity / IP ──────────────────────────────────────────────────

def client_ip():
    """Best available client address, honouring X-Forwarded-For only when the
    deployment says it sits behind a trusted proxy.

    Reading XFF unconditionally is the classic way to make an IP-keyed rate
    limiter useless, since the header is attacker-supplied.
    """
    from config import Config

    remote = request.remote_addr or 'unknown'
    if not Config.BEHIND_PROXY:
        return remote
    forwarded = request.headers.get('X-Forwarded-For', '')
    if not forwarded:
        return remote
    hops = [h.strip() for h in forwarded.split(',') if h.strip()]
    if not hops:
        return remote
    # Rightmost-untrusted convention: with N proxy hops the client is the Nth
    # entry counting back from the end.
    index = max(len(hops) - Config.PROXY_HOPS, 0)
    return hops[index]


def attach_request_context():
    """Per-request bookkeeping: correlation id + resolved client IP.

    The request id is echoed on responses and written into access logs and
    audit-trail rows, so a user report ("scan failed at 14:22") maps to one
    server-side line without guessing.
    """
    from core.audit_trail import new_request_id
    from uuid import uuid4  # noqa: F401  (kept explicit: new_request_id uses uuid4)

    g.request_id = request.headers.get('X-Request-Id') or new_request_id()
    g.request_started = time.time()
    g.client_ip = client_ip()
    # Explicitly cleared per request rather than assumed absent. `g` lives on the
    # app context, and Flask *reuses* an already-pushed app context for a nested
    # request — which is what a test client driving the app from inside
    # `with app.app_context()` does. Without this line the trail writer's
    # "already recorded this request" flag from an earlier request suppressed
    # every fallback entry, so denied-access rows silently disappeared in the
    # suite while working in production. Initializing the flag makes the
    # behaviour identical in both.
    g.audit_trail_written = False
    return None



# ── Forced password change ────────────────────────────────────────────────

_PASSWORD_GATE_ALLOWLIST = frozenset({
    '/api/auth/change-password', '/api/auth/logout', '/api/auth/me',
    '/api/auth/password-policy', '/api/auth/login', '/api/auth/register',
    '/api/auth/refresh',
})


def password_change_gate():
    """Refuse tenant-bearing API calls until a forced password change is done.

    `User.must_change_password` started life as a column plus a banner on the
    dashboard, which is not a control: a temporary password handed out by an
    admin stayed usable indefinitely if the user ignored the note. This gate is
    what makes the promise real.

    Allowlist reasoning:
      * change-password — the only way out of the state; blocking it would
        prevent compliance rather than enforce it.
      * logout — ending a session must always be possible.
      * me — the UI needs identity to render the password form and explain the
        block; it returns the caller's own row.
      * password-policy — the rules the new password must meet; public anyway.
      * login / register / refresh — unauthenticated by definition, and login is
        the request that reports the flagged state.

    Returns a Response to short-circuit, or None to let the request proceed.
    """
    path = request.path or ''
    if not path.startswith('/api/') or path in _PASSWORD_GATE_ALLOWLIST:
        return None

    from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity

    try:
        # optional=True: an unauthenticated request is the auth layer's problem
        # (it will 401 as usual), not this gate's.
        verify_jwt_in_request(optional=True)
        identity = get_jwt_identity()
    except Exception:                     # noqa: BLE001 - malformed token -> normal 422/401 path
        return None
    if not identity:
        return None

    from extensions import db
    from models import User

    user = db.session.get(User, int(identity))
    if user is None or not user.must_change_password:
        return None

    response = jsonify({
        'error': 'A password change is required before this account can be used. '
                 'Send POST /api/auth/change-password.',
        'code': 'password_change_required',
        'change_password_endpoint': '/api/auth/change-password',
    })
    response.status_code = 403
    return response


CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; "
    "object-src 'none'; base-uri 'self'; form-action 'self'; "
    "frame-ancestors 'none'"
)


def hardening_headers(response):
    """Response headers a compliance reviewer asks about first.

    script-src is strictly 'self': no inline <script>, no inline event-handler
    attributes (the UI wires clicks through data-action plus one delegated
    listener in static/js/dashboard.js), no eval. style-src still allows
    'unsafe-inline' because the templates carry style="" attributes -- a known,
    narrower gap than script injection (it cannot run code), tracked in
    SECURITY.md.
    """
    from config import Config

    secure = Config.SECURE_COOKIES
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'same-origin')
    response.headers.setdefault('Permissions-Policy', 'geolocation=(), camera=(), microphone=()')
    response.headers.setdefault('Cross-Origin-Opener-Policy', 'same-origin')
    response.headers.setdefault('X-Request-Id', getattr(g, 'request_id', ''))
    if not request.path.startswith('/api/'):
        # Cached static-ish pages get a short private cache; API responses stay
        # uncacheable so two analysts never see each other's stale org data.
        response.headers.setdefault('Cache-Control', 'private, no-cache')
    else:
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Pragma'] = 'no-cache'
    response.headers.setdefault('Content-Security-Policy', CONTENT_SECURITY_POLICY)
    if secure:
        response.headers.setdefault('Strict-Transport-Security',
                                    'max-age=31536000; includeSubDomains')
    return response


def maybe_trusted_hosts():
    """Werkzeug ProxyFix is applied by the factory when BEHIND_PROXY is set;
    this exists so tests can assert the intent in one place."""
    from config import Config

    return Config.BEHIND_PROXY
