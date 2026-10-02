"""Phase 0 hardening: config/startup behavior.

These pin decisions that are easy to regress silently: a missing secret must
stop the app (not fall back to a published default), CORS must be closed unless
an origin is named, and the debugger must never be on by default.
"""

import os
import subprocess
import sys

import pytest

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.mark.parametrize('overrides', [
    {'SECRET_KEY': ''},
    {'SECRET_KEY': 'short'},
    {'SECRET_KEY': 'dev-only-insecure-key-change-me'},
    {'JWT_SECRET_KEY': 'change-me-to-a-different-random-64-char-string'},
    {'JWT_SECRET_KEY': 'x' * 48},
])
def test_weak_signing_secret_refuses_to_start(app, overrides):
    from app import create_app

    with pytest.raises(RuntimeError, match='Refusing to start'):
        create_app({**{'SECRET_KEY': 'a1' * 24, 'JWT_SECRET_KEY': 'b2' * 24,
                       'SQLALCHEMY_DATABASE_URI': 'sqlite://', 'TESTING': True,
                       'RATE_LIMIT_ENABLED': False}, **overrides})


def test_missing_env_secret_stops_the_process():
    """No fallback default: importing the app with no secrets at all must fail."""
    env = {k: v for k, v in os.environ.items() if k not in ('SECRET_KEY', 'JWT_SECRET_KEY')}
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    # Run from a directory with no .env so python-dotenv can't supply one.
    code = ("import sys; sys.path.insert(0, %r); import app" % BACKEND_DIR)
    result = subprocess.run([sys.executable, '-c', code], cwd=os.path.dirname(BACKEND_DIR),
                            env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode != 0
    assert 'Refusing to start' in (result.stderr + result.stdout)


def test_cors_is_closed_by_default(client):
    response = client.get('/api/auth/password-policy', headers={'Origin': 'http://evil.example'})
    assert response.status_code == 200
    assert 'Access-Control-Allow-Origin' not in response.headers


def test_debug_is_off_by_default(app):
    assert app.debug is False
    source = open(os.path.join(BACKEND_DIR, 'app.py'), encoding='utf-8').read()
    assert "debug=(Config.ENVIRONMENT" not in source  # never keyed off the env label
    assert 'FLASK_DEBUG' in source
