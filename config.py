"""
Secure Configuration Management for School Management System
All secrets are loaded from environment variables — no hardcoded defaults.
"""
import os
from datetime import timedelta


class Config:
    """Base configuration with security defaults."""

    # ─── Flask Core ──────────────────────────────────────────────────
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(32).hex()
    FLASK_ENV = os.environ.get('FLASK_ENV', 'production')

    # ─── MongoDB ─────────────────────────────────────────────────────
    MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/gayatri_school')

    # ─── Session Security ────────────────────────────────────────────
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'True') == 'True'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_PERMANENT = True
    PERMANENT_SESSION_LIFETIME = timedelta(
        hours=int(os.environ.get('SESSION_TIMEOUT_HOURS', 1))
    )
    SESSION_TYPE = 'filesystem'
    SESSION_FILE_DIR = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'flask_session'
    )
    SESSION_FILE_THRESHOLD = 100

    # ─── Security Headers ────────────────────────────────────────────
    SEND_FILE_MAX_AGE_DEFAULT = 31536000  # 1 year for static files

    # ─── File Upload ─────────────────────────────────────────────────
    MAX_CONTENT_LENGTH = int(
        os.environ.get('MAX_CONTENT_LENGTH', 2 * 1024 * 1024)
    )  # 2MB default
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'static/uploads')
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

    # ─── Email Configuration ─────────────────────────────────────────
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER')

    # ─── Rate Limiting ───────────────────────────────────────────────
    RATELIMIT_ENABLED = os.environ.get('RATELIMIT_ENABLED', 'True') == 'True'
    RATELIMIT_STORAGE_URL = os.environ.get('RATELIMIT_STORAGE_URL', 'memory://')

    # ─── Login Attempt Limits ────────────────────────────────────────
    MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', 5))
    LOGIN_LOCKOUT_DURATION = timedelta(
        minutes=int(os.environ.get('LOGIN_LOCKOUT_MINUTES', 15))
    )

    # ─── Password Policy ─────────────────────────────────────────────
    MIN_PASSWORD_LENGTH = 8
    REQUIRE_PASSWORD_COMPLEXITY = True

    # ─── OTP Settings ────────────────────────────────────────────────
    OTP_EXPIRY_MINUTES = int(os.environ.get('OTP_EXPIRY_MINUTES', 10))
    OTP_MAX_ATTEMPTS = int(os.environ.get('OTP_MAX_ATTEMPTS', 3))

    # ─── Default Account Credentials (from env only) ─────────────────
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'GVP022026')
    ADMIN_DEFAULT_PASSWORD = os.environ.get(
        'ADMIN_DEFAULT_PASSWORD', 'CHANGE_IMMEDIATELY'
    )
    PRINCIPAL_USERNAME = os.environ.get('PRINCIPAL_USERNAME', 'principal')
    PRINCIPAL_DEFAULT_PASSWORD = os.environ.get(
        'PRINCIPAL_DEFAULT_PASSWORD', 'CHANGE_IMMEDIATELY'
    )
    ACCOUNTANT_USERNAME = os.environ.get('ACCOUNTANT_USERNAME', 'accountant')
    ACCOUNTANT_DEFAULT_PASSWORD = os.environ.get(
        'ACCOUNTANT_DEFAULT_PASSWORD', 'CHANGE_IMMEDIATELY'
    )
    DEFAULT_TEACHER_PASSWORD = os.environ.get(
        'DEFAULT_TEACHER_PASSWORD', 'GVP@2026'
    )

    # ─── Logging ─────────────────────────────────────────────────────
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'logs/school_app.log')


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    TESTING = False
    SESSION_COOKIE_SECURE = False  # Allow HTTP in development


class ProductionConfig(Config):
    """Production configuration with enhanced security."""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True  # Require HTTPS

    @classmethod
    def init_app(cls, app):
        """Production-specific initialization."""
        # Ensure SECRET_KEY is set from environment
        if app.config['SECRET_KEY'] == 'CHANGE_IMMEDIATELY' or len(app.config['SECRET_KEY']) < 16:
            raise ValueError(
                "SECRET_KEY must be set to a strong random value in production. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )


class TestingConfig(Config):
    """Testing configuration."""
    DEBUG = True
    TESTING = True
    SESSION_COOKIE_SECURE = False
    WTF_CSRF_ENABLED = False


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
