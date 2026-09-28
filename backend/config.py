"""Application configuration.

Everything comes from the environment so a container image can be promoted
between staging and production without a code change — the same image plus a
different set of env vars. Defaults are development-safe (SQLite, permissive
CORS) and `Config.validate()` refuses to boot a "production" profile that still
carries a placeholder secret, which is the single most common way a Flask app
like this ends up on a breach report.
"""

import os
from datetime import timedelta

_TRUTHY = {'1', 'true', 'yes', 'on'}
_PLACEHOLDER_MARKERS = ('change-me', 'change_me', 'dev-only-insecure', 'secret',
                        'password', 'xxxx', 'your-', 'placeholder')


def _env_bool(name, default=False):
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in _TRUTHY


def _env_int(name, default, minimum=None, maximum=None):
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == '':
        return default
    try:
        value = int(str(raw).strip())
    except ValueError:
        raise RuntimeError(f'{name} must be an integer, got {raw!r}')
    if minimum is not None and value < minimum:
        raise RuntimeError(f'{name} must be >= {minimum}, got {value}')
    if maximum is not None and value > maximum:
        raise RuntimeError(f'{name} must be <= {maximum}, got {value}')
    return value


def _env_list(name, default):
    raw = os.environ.get(name)
    if not raw:
        return list(default)
    return [item.strip() for item in raw.split(',') if item.strip()]


def _looks_placeholder(value):
    if not value:
        return True
    lowered = value.lower()
    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS) or len(value) < 32


class Config:
    # ── Core ──────────────────────────────────────────────────────────────
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-only-insecure-key-change-me')
    ENVIRONMENT = os.environ.get('ENVIRONMENT') or os.environ.get('FLASK_ENV', 'development')
    # Relative sqlite:/// URIs are resolved by Flask-SQLAlchemy relative to
    # app.instance_path (already .../backend/instance) — do NOT prefix with
    # "instance/" here or it doubles up to instance/instance/audinexia.db.
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///audinexia.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Pool tuning only applies to a real server-side DB; SQLAlchemy ignores
    # pool kwargs for SQLite. Sized for a 4-worker gunicorn deployment.
    # SQLite (file or memory) does not accept pool sizing at all — the memory
    # dialect in particular is built with StaticPool and raises TypeError on
    # pool_size, which broke any app built with a sqlite :memory: URI (the
    # documented way to embed the platform in tests). The engine options are
    # therefore only attached for server-side databases.
    _POOL_OPTIONS = {
        'pool_size': _env_int('DB_POOL_SIZE', 10, minimum=1),
        'max_overflow': _env_int('DB_MAX_OVERFLOW', 20, minimum=0),
        'pool_pre_ping': True,
        'pool_recycle': _env_int('DB_POOL_RECYCLE_SECONDS', 1800, minimum=30),
    }
    SQLALCHEMY_ENGINE_OPTIONS = (
        {} if os.environ.get('DATABASE_URL', 'sqlite:///audinexia.db').startswith('sqlite')
        else _POOL_OPTIONS
    )
    SQLALCHEMY_ECHO = _env_bool('SQL_ECHO', False)

    # ── Auth ──────────────────────────────────────────────────────────────
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'dev-only-insecure-jwt-key-change-me')
    JWT_ALGORITHM = os.environ.get('JWT_ALGORITHM', 'HS256')
    # 30 min access / 7 d refresh is a deliberate trade for a compliance tool:
    # short-lived tokens limit the blast radius of a stolen token, and the
    # dashboard refreshes silently (static/js/auth.js) so it costs the user
    # nothing in day-to-day use.
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=_env_int('JWT_ACCESS_MINUTES', 30, minimum=5, maximum=720))
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=_env_int('JWT_REFRESH_DAYS', 7, minimum=1, maximum=90))
    JWT_ERROR_MESSAGE_KEY = 'msg'
    # Blocklist is DB-backed (models.RevokedToken) so revocation is correct
    # across gunicorn workers and survives a restart.
    JWT_BLOCKLIST_ENABLED = True

    MIN_PASSWORD_LENGTH = _env_int('MIN_PASSWORD_LENGTH', 10, minimum=8, maximum=128)
    # Per-org-user attempts before the account is locked for LOCKOUT_MINUTES.
    # Counted in-process (see security.py): an in-memory counter is per-worker,
    # which is enough to stop a single-socket brute-force run but is NOT a
    # substitute for rate limiting at the edge in a multi-worker deployment.
    LOGIN_MAX_ATTEMPTS = _env_int('LOGIN_MAX_ATTEMPTS', 8, minimum=3, maximum=100)
    LOGIN_LOCKOUT_MINUTES = _env_int('LOGIN_LOCKOUT_MINUTES', 15, minimum=1, maximum=1440)

    # ── Uploads ───────────────────────────────────────────────────────────
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
    REPORT_FOLDER = os.environ.get('REPORT_FOLDER', 'reports')
    MAX_CONTENT_LENGTH = _env_int('MAX_UPLOAD_MB', 50, minimum=1, maximum=200) * 1024 * 1024
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'docx'}

    # ── HTTP surface ──────────────────────────────────────────────────────
    # CORS is only needed by a separate-origin SPA. Same-origin (the served
    # dashboard) never sends an Origin header that must be matched, so the
    # production default is empty = no cross-origin access at all.
    CORS_ORIGINS = _env_list('CORS_ORIGINS', ['*'] if os.environ.get('ENVIRONMENT', '').lower() != 'production' else [])
    # Trust X-Forwarded-* only when explicitly told the app sits behind a
    # proxy; trusting it by default lets a client spoof its own IP and bypass
    # the rate limiter.
    BEHIND_PROXY = _env_bool('BEHIND_PROXY', False)
    PROXY_HOPS = _env_int('PROXY_HOPS', 1, minimum=1, maximum=10)

    RATE_LIMIT_ENABLED = _env_bool('RATE_LIMIT_ENABLED', True)
    RATE_LIMIT_DEFAULT = os.environ.get('RATE_LIMIT_DEFAULT', '240 per hour')
    RATE_LIMIT_LOGIN = os.environ.get('RATE_LIMIT_LOGIN', '10 per 5 minutes')
    RATE_LIMIT_REGISTER = os.environ.get('RATE_LIMIT_REGISTER', '6 per hour')
    RATE_LIMIT_SCAN = os.environ.get('RATE_LIMIT_SCAN', '60 per hour')
    # 'memory' is per-process. 'db' shares counters across workers through
    # api_rate_limit_buckets at the cost of one write per limited request.
    RATE_LIMIT_STORE = os.environ.get('RATE_LIMIT_STORE', 'memory').lower()

    # Comma-separated, e.g. "10.0.0.0/8,203.0.113.5". Trusted only for the
    # purpose of reading X-Forwarded-For.
    TRUSTED_PROXIES = _env_list('TRUSTED_PROXIES', [])

    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()
    LOG_FORMAT = os.environ.get('LOG_FORMAT', 'text').lower()   # 'text' | 'json'
    # Self-signed / no-TLS is fine locally, wrong for anything reachable.
    # Setting SECURE_COOKIES=true is the documented switch that turns on the
    # hardening headers (HSTS, https-only) an auditor will look for.
    SECURE_COOKIES = _env_bool('SECURE_COOKIES', False)
    ENABLE_CSP = _env_bool('ENABLE_CSP', True)

    # Monitoring scheduler: an in-process convenience for single-worker
    # deployments. Multi-worker/production should run `flask monitor run-due`
    # from cron instead (see core/monitoring.py's module docstring).
    MONITORING_SCHEDULER_ENABLED = _env_bool('MONITORING_SCHEDULER_ENABLED', False)
    MONITORING_SCHEDULER_INTERVAL_SECONDS = _env_int('MONITORING_SCHEDULER_INTERVAL_SECONDS', 3600,
                                                     minimum=60, maximum=86400)

    # Compliance defaults surfaced to the UI/API; not hidden magic numbers.
    DEFAULT_POLICY_REVIEW_INTERVAL_DAYS = _env_int('DEFAULT_POLICY_REVIEW_INTERVAL_DAYS', 180,
                                                    minimum=1, maximum=3650)
    DEFAULT_VENDOR_REVIEW_INTERVAL_DAYS = _env_int('DEFAULT_VENDOR_REVIEW_INTERVAL_DAYS', 365,
                                                   minimum=1, maximum=3650)
    AUDIT_TRAIL_RETENTION_DAYS = _env_int('AUDIT_TRAIL_RETENTION_DAYS', 0, minimum=0)  # 0 = keep forever

    APP_VERSION = os.environ.get('APP_VERSION', '4.0.0')
    BUILD_SHA = os.environ.get('BUILD_SHA', '')
    API_TITLE = 'Audinexia GRC Platform API'

    @staticmethod
    def validate():
        """Return a list of (severity, message) findings for the current config.

        Called at app creation: 'error' entries raise in production so a
        misconfigured deployment fails loudly at boot instead of running
        insecurely and quietly.
        """
        findings = []
        production = Config.ENVIRONMENT.lower() in ('production', 'prod')

        if _looks_placeholder(Config.SECRET_KEY):
            findings.append(('error' if production else 'warning',
                             'SECRET_KEY is a placeholder or shorter than 32 characters'))
        if _looks_placeholder(Config.JWT_SECRET_KEY):
            findings.append(('error' if production else 'warning',
                             'JWT_SECRET_KEY is a placeholder or shorter than 32 characters'))
        if Config.SECRET_KEY == Config.JWT_SECRET_KEY:
            findings.append(('error' if production else 'warning',
                             'SECRET_KEY and JWT_SECRET_KEY are identical; use independent secrets'))
        if production and not Config.CORS_ORIGINS:
            findings.append(('info', 'CORS_ORIGINS is empty — same-origin dashboard only '
                                     '(correct unless a separate SPA calls this API)'))
        if production and not Config.SECURE_COOKIES:
            findings.append(('warning', 'SECURE_COOKIES=false in production: hardening headers '
                                        '(HSTS, https-only cookies) are off'))
        if production and Config.SQLALCHEMY_DATABASE_URI.startswith('sqlite'):
            findings.append(('warning', 'SQLite in production: fine for a single-node deployment, '
                                        'but concurrent writers serialize on one file — prefer Postgres'))
        if production and Config.RATE_LIMIT_STORE == 'memory':
            findings.append(('warning', 'RATE_LIMIT_STORE=memory is per-worker; set '
                                        'RATE_LIMIT_STORE=db for shared counters under gunicorn'))
        if Config.RATE_LIMIT_STORE not in ('memory', 'db'):
            findings.append(('error', f"RATE_LIMIT_STORE must be 'memory' or 'db', got "
                                      f"{Config.RATE_LIMIT_STORE!r}"))
        return findings
