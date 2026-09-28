"""Logging setup: structured, request-correlated, and credential-safe.

Two formats, one code path:
* `text` for local development (readable in a terminal).
* `json` for production, so the platform's log pipeline can index fields
  instead of parsing prose. Set LOG_FORMAT=json.

Every access-log line carries request_id, actor and org so a support report maps
to exactly one request without guessing. Fields, not format strings, are the
unit — a JSON log line that cannot be joined to a tenant is not useful in an
incident.

Nothing in the request body is ever logged: policy documents are confidential by
definition, and uploads go through multipart where a body dump would leak
customer documents into a log aggregator.
"""

import json
import logging
import sys
import time
from logging import LogRecord

SENSITIVE_QUERY_KEYS = ('token', 'key', 'secret', 'password', 'code')

# Levels for third-party loggers that are chatty at INFO and useless at DEBUG
# for this app's operators.
NOISY_LOGGERS = {
    'werkzeug': logging.WARNING,   # replaced by our own access log
    'pdfminer': logging.WARNING,   # pdfplumber's parser is extremely verbose
    'fontTools': logging.WARNING,
    'sqlalchemy.engine.Engine': logging.WARNING,
}


class JsonFormatter(logging.Formatter):
    """One JSON object per line, including exception info as a nested field."""

    def format(self, record: LogRecord) -> str:
        payload = {
            'ts': time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(record.created))
                  + f'.{int(record.msecs):03d}Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }
        for field in ('request_id', 'method', 'path', 'status', 'duration_ms',
                      'user_id', 'org_id', 'client_ip', 'event'):
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value
        if record.exc_info:
            payload['exception'] = self.formatException(record.exc_info)
        if getattr(record, 'extra_fields', None):
            payload.update(record.extra_fields)
        return json.dumps(payload, ensure_ascii=True, default=str)


class TextFormatter(logging.Formatter):
    def format(self, record: LogRecord) -> str:
        base = super().format(record)
        parts = []
        for field in ('request_id', 'user_id', 'org_id', 'status'):
            value = getattr(record, field, None)
            if value is not None:
                parts.append(f'{field}={value}')
        return f'{base}' + (f'  [{", ".join(parts)}]' if parts else '')


def redact_path(raw_path: str) -> str:
    """Strip credential-shaped query parameters before a path reaches a log."""
    if '?' not in raw_path:
        return raw_path
    head, _, query = raw_path.partition('?')
    kept = []
    for pair in query.split('&'):
        key = pair.split('=', 1)[0].lower()
        kept.append(f'{key}=<redacted>' if any(s in key for s in SENSITIVE_QUERY_KEYS) else pair)
    return f'{head}?{"&".join(kept)}' if kept else head


def configure_logging(app):
    """Attach a stream handler to the app logger and wire per-request access
    logging. Idempotent: re-running (Flask's reloader, or a test creating many
    apps) does not stack duplicate handlers."""
    level = getattr(logging, app.config.get('LOG_LEVEL', 'INFO'), logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    if app.config.get('LOG_FORMAT', 'text') == 'json':
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(TextFormatter(
            '%(asctime)s %(levelname)-7s %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
        ))

    app.logger.handlers.clear()
    app.logger.addHandler(handler)
    app.logger.setLevel(level)
    app.propagate = False

    for name, level_override in NOISY_LOGGERS.items():
        target = logging.getLogger(name)
        target.handlers.clear()
        target.setLevel(level_override)
        target.propagate = False

    from flask import g, request

    @app.after_request
    def _access_log(response):
        started = getattr(g, 'request_started', None)
        duration_ms = round((time.time() - started) * 1000, 1) if started else None
        # Skip the two highest-frequency, lowest-signal paths so the log stays
        # readable during a demo where the dashboard polls.
        if request.path not in ('/healthz', '/api/monitoring/summary'):
            claims = getattr(g, 'jwt_claims', None) or {}
            app.logger.info(
                '%s %s -> %s', request.method, redact_path(request.path), response.status_code,
                extra={
                    'extra_fields': {
                        'request_id': getattr(g, 'request_id', None),
                        'method': request.method,
                        'path': redact_path(request.path),
                        'status': response.status_code,
                        'duration_ms': duration_ms,
                        'user_id': claims.get('sub'),
                        'org_id': claims.get('org_id'),
                        'client_ip': getattr(g, 'client_ip', None),
                        'event': 'http_request',
                    }
                },
            )
        return response

    @app.before_request
    def _capture_claims():
        """Stash claims for the access log without requiring an endpoint to be
        JWT-protected — an anonymous 401 line is still worth correlating."""
        try:
            from flask_jwt_extended import verify_jwt_in_request
            from flask_jwt_extended import get_jwt

            verify_jwt_in_request(optional=True)
            g.jwt_claims = get_jwt() or {}
        except Exception:
            g.jwt_claims = {}
        return None

    return app
