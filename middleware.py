"""
Security Middleware for School Management System
Centralizes request/response security processing.
"""
import uuid
import time
import logging
from functools import wraps
from flask import request, g, session, abort

logger = logging.getLogger(__name__)


class SecurityMiddleware:
    """WSGI middleware for security headers and request tracking."""

    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """Register before/after request hooks."""
        app.before_request(self._before_request)
        app.after_request(self._after_request)

    @staticmethod
    def _before_request():
        """Attach request metadata for logging and tracing."""
        g.request_id = uuid.uuid4().hex[:12]
        g.request_start = time.time()

    @staticmethod
    def _after_request(response):
        """Inject security headers into every response."""
        # ── Strict Transport Security (HSTS) ───────────────────────────
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        # ── Anti-Clickjacking ────────────────────────────────────────
        response.headers['X-Frame-Options'] = 'DENY'

        # ── Prevent MIME-type sniffing ───────────────────────────────
        response.headers['X-Content-Type-Options'] = 'nosniff'

        # ── XSS Auditor (legacy browsers) ────────────────────────────
        response.headers['X-XSS-Protection'] = '1; mode=block'

        # ── Referrer Policy ──────────────────────────────────────────
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # ── Permissions Policy ───────────────────────────────────────
        response.headers['Permissions-Policy'] = (
            'camera=(), microphone=(), geolocation=(), '
            'payment=(), usb=(), magnetometer=()'
        )

        # ── Remove server identification ─────────────────────────────
        response.headers.pop('Server', None)
        response.headers.pop('X-Powered-By', None)

        # ── Cache control for authenticated pages ────────────────────
        if _is_authenticated_route():
            response.headers['Cache-Control'] = (
                'no-store, no-cache, must-revalidate, '
                'post-check=0, pre-check=0, max-age=0'
            )
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '-1'

        # ── Request tracking header (internal) ───────────────────────
        response.headers['X-Request-ID'] = getattr(g, 'request_id', 'unknown')

        # ── Log slow requests ────────────────────────────────────────
        elapsed = time.time() - getattr(g, 'request_start', time.time())
        if elapsed > 2.0:
            logger.warning(
                'Slow request: %s %s took %.2fs [req_id=%s]',
                request.method, request.path, elapsed,
                getattr(g, 'request_id', 'unknown')
            )

        return response


def _is_authenticated_route():
    """Check if the current route should have no-cache headers."""
    sensitive_keywords = (
        'dashboard', 'login', 'admin', 'teacher', 'student',
        'accountant', 'principal', 'salary', 'payroll', 'fee',
        'attendance', 'profile', 'password', 'logout'
    )
    path = request.path.lower()
    return any(kw in path for kw in sensitive_keywords)


def validate_content_type(f):
    """Decorator to enforce JSON content-type on API endpoints."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ('POST', 'PUT', 'PATCH'):
            if request.content_type and 'json' in request.content_type:
                if not request.is_json:
                    abort(400, description='Invalid JSON body')
        return f(*args, **kwargs)
    return decorated
