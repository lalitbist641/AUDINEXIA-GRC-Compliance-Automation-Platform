import os
import sys
from datetime import timedelta


def _require(name, min_len=32):
    """Refuse to boot with a missing, too-short, or default-placeholder
    secret. A prior version of this file fell back to a hardcoded string
    ('dev-only-insecure-key-change-me') when the env var was unset -- an
    attacker who knew that string (e.g. from reading this open-source repo)
    could forge a valid JWT for any role. There is no safe default for a
    signing secret; the only correct behavior is to refuse to start."""
    value = os.environ.get(name, "")
    if len(value) < min_len or "change-me" in value.lower():
        sys.exit(
            f"FATAL: {name} is missing or too weak (must be at least {min_len} "
            f"characters and not contain 'change-me'). Set it in the environment "
            f"-- see .env.example. Generate one with: "
            f"python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    return value


class Config:
    SECRET_KEY = _require("SECRET_KEY")
    # Relative sqlite:/// URIs are resolved by Flask-SQLAlchemy relative to
    # app.instance_path (already .../backend/instance) -- do NOT prefix with
    # "instance/" here or it doubles up to instance/instance/audinexia.db.
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///audinexia.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    JWT_SECRET_KEY = _require("JWT_SECRET_KEY")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=30)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)

    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
    REPORT_FOLDER = os.environ.get('REPORT_FOLDER', 'reports')
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'docx'}

    FLASK_DEBUG = os.environ.get('FLASK_DEBUG', '0') == '1'


class TestConfig(Config):
    """For automated tests (none exist yet -- see CHANGELOG/SECURITY.md known
    gaps -- but this is here so a future test suite has a config that never
    touches real secrets or the dev database). Overrides _require()'s
    behavior by setting explicit throwaway values BEFORE Config's class body
    would otherwise call _require() against the real environment."""
    SECRET_KEY = "test-only-secret-not-for-real-use-0123456789abcdef"
    JWT_SECRET_KEY = "test-only-jwt-secret-not-for-real-use-0123456789ab"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    FLASK_DEBUG = False
