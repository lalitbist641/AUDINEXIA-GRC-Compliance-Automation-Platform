import os
from datetime import timedelta


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-only-insecure-key-change-me')
    # Relative sqlite:/// URIs are resolved by Flask-SQLAlchemy relative to
    # app.instance_path (already .../backend/instance) -- do NOT prefix with
    # "instance/" here or it doubles up to instance/instance/audinexia.db.
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///audinexia.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'dev-only-insecure-jwt-key-change-me')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=30)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)

    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
    REPORT_FOLDER = os.environ.get('REPORT_FOLDER', 'reports')
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'docx'}
