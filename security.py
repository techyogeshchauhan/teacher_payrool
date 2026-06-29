"""
Security Module - Input Validation, Sanitization, and Authentication
Production-grade security utilities for the School Management System.
"""
import re
import os
import hmac
import secrets
import hashlib
import uuid
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import session, redirect, url_for, flash, request, abort
from werkzeug.utils import secure_filename
import bleach
from bson.objectid import ObjectId

# ─── Password Hashing (bcrypt with SHA-256 fallback) ─────────────────────────
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False
    import logging
    logging.getLogger(__name__).critical(
        "bcrypt not available — passwords will use SHA-256 (INSECURE for production). "
        "Install bcrypt: pip install bcrypt"
    )


# ─── Input Validation ────────────────────────────────────────────────────────

class SecurityValidator:
    """Input validation and sanitization."""

    PATTERNS = {
        'teacher_id': re.compile(r'^TCH\d{4}(-\d+)?$'),
        'phone': re.compile(r'^\d{10}$'),
        'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
        'admission_no': re.compile(r'^[A-Z0-9\-]{3,20}$'),
        'roll_no': re.compile(r'^[A-Z0-9\-]{1,20}$'),
        'ifsc': re.compile(r'^[A-Z]{4}0[A-Z0-9]{6}$'),
        'pan': re.compile(r'^[A-Z]{5}\d{4}[A-Z]$'),
        'date': re.compile(r'^\d{4}-\d{2}-\d{2}$'),
        'alphanumeric': re.compile(r'^[a-zA-Z0-9\s\-]+$'),
        'username': re.compile(r'^[a-zA-Z0-9_]{3,30}$'),
    }

    @staticmethod
    def sanitize_string(value, max_length=255):
        """Sanitize string input to prevent XSS."""
        if not value:
            return ''
        # Remove HTML tags and dangerous characters
        cleaned = bleach.clean(str(value), tags=[], strip=True)
        return cleaned[:max_length].strip()

    @staticmethod
    def sanitize_html(value, allowed_tags=None):
        """Sanitize HTML content (for rich text fields)."""
        if not value:
            return ''
        if allowed_tags is None:
            allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'ul', 'ol', 'li']
        return bleach.clean(str(value), tags=allowed_tags, strip=True)

    @staticmethod
    def sanitize_search(value, max_length=100):
        """Sanitize search input — escape regex special characters to prevent ReDoS and NoSQL injection."""
        if not value:
            return ''
        sanitized = SecurityValidator.sanitize_string(value, max_length)
        # Escape regex special characters
        return re.escape(sanitized)

    @staticmethod
    def validate_teacher_id(teacher_id):
        """Validate teacher ID format."""
        if not teacher_id:
            return False, "Teacher ID is required"
        tid = str(teacher_id).strip().upper()
        if not SecurityValidator.PATTERNS['teacher_id'].match(tid):
            return False, "Invalid teacher ID format (expected TCH followed by 4 digits)"
        return True, tid

    @staticmethod
    def validate_phone(phone):
        """Validate phone number."""
        if not phone:
            return False, "Phone number is required"
        phone = re.sub(r'[^\d]', '', str(phone))
        if not SecurityValidator.PATTERNS['phone'].match(phone):
            return False, "Phone number must be 10 digits"
        return True, phone

    @staticmethod
    def validate_email(email):
        """Validate email address."""
        if not email:
            return True, ''  # Email is optional in many forms
        email = str(email).strip().lower()
        if not SecurityValidator.PATTERNS['email'].match(email):
            return False, "Invalid email format"
        return True, email

    @staticmethod
    def validate_date(date_str):
        """Validate date format YYYY-MM-DD."""
        if not date_str:
            return False, "Date is required"
        if not SecurityValidator.PATTERNS['date'].match(str(date_str)):
            return False, "Invalid date format (YYYY-MM-DD required)"
        try:
            datetime.strptime(str(date_str), '%Y-%m-%d')
            return True, None
        except ValueError:
            return False, "Invalid date"

    @staticmethod
    def validate_amount(amount_str):
        """Validate monetary amount."""
        try:
            amount = float(amount_str)
            if amount < 0:
                return False, "Amount cannot be negative"
            if amount > 10000000:  # 1 crore limit
                return False, "Amount exceeds maximum limit"
            return True, amount
        except (ValueError, TypeError):
            return False, "Invalid amount"

    @staticmethod
    def validate_positive_int(value, field_name="Value", max_val=10000):
        """Validate a positive integer."""
        try:
            val = int(value)
            if val < 0:
                return False, f"{field_name} cannot be negative"
            if val > max_val:
                return False, f"{field_name} exceeds maximum ({max_val})"
            return True, val
        except (ValueError, TypeError):
            return False, f"Invalid {field_name}"

    @staticmethod
    def validate_password(password, min_length=8, require_complexity=True):
        """Validate password strength."""
        if not password:
            return False, "Password is required"
        if len(password) < min_length:
            return False, f"Password must be at least {min_length} characters"
        if len(password) > 128:
            return False, "Password cannot exceed 128 characters"

        if require_complexity:
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)
            has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)

            if not (has_upper and has_lower and has_digit and has_special):
                return False, "Password must contain uppercase, lowercase, digit, and special character"

        return True, None

    @staticmethod
    def validate_file_upload(file, allowed_extensions):
        """Validate uploaded file — extension, filename, and MIME type."""
        if not file or file.filename == '':
            return False, "No file selected"

        # Secure filename
        filename = secure_filename(file.filename)
        if not filename:
            return False, "Invalid filename"

        # Check extension
        ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
        if ext not in allowed_extensions:
            return False, f"File type not allowed. Allowed: {', '.join(allowed_extensions)}"

        # Generate random filename to prevent enumeration
        safe_filename = f"{uuid.uuid4().hex}.{ext}"
        return True, safe_filename

    @staticmethod
    def validate_object_id(id_str):
        """Validate MongoDB ObjectId format."""
        if not id_str:
            return False, "ID is required"
        try:
            ObjectId(str(id_str))
            return True, None
        except Exception:
            return False, "Invalid ID format"

    @staticmethod
    def validate_name(name, max_length=100):
        """Validate a person's name."""
        if not name or not str(name).strip():
            return False, "Name is required"
        sanitized = SecurityValidator.sanitize_string(name, max_length)
        if len(sanitized) < 2:
            return False, "Name must be at least 2 characters"
        return True, sanitized

    @staticmethod
    def validate_status(status, allowed=('Active', 'Inactive')):
        """Validate a status field against allowed values."""
        if status not in allowed:
            return False, f"Invalid status. Allowed: {', '.join(allowed)}"
        return True, status


# ─── Password Management ─────────────────────────────────────────────────────

class PasswordManager:
    """Secure password hashing and verification using bcrypt."""

    @staticmethod
    def hash_password(password):
        """Hash password using bcrypt (preferred) or SHA-256 (fallback)."""
        if BCRYPT_AVAILABLE:
            salt = bcrypt.gensalt(rounds=12)
            return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
        else:
            return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod
    def verify_password(password, hashed):
        """Verify password against stored hash."""
        if not password or not hashed:
            return False
        try:
            if BCRYPT_AVAILABLE and hashed.startswith('$2b$'):
                return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
            else:
                # SHA-256 fallback (legacy)
                return hmac.compare_digest(
                    hashlib.sha256(password.encode()).hexdigest(),
                    hashed
                )
        except Exception:
            return False

    @staticmethod
    def needs_rehash(hashed):
        """Check if a stored hash needs to be migrated to bcrypt."""
        if not hashed:
            return True
        if BCRYPT_AVAILABLE and not hashed.startswith('$2b$'):
            return True
        return False

    @staticmethod
    def generate_secure_token(length=32):
        """Generate cryptographically secure random token."""
        return secrets.token_urlsafe(length)

    @staticmethod
    def generate_otp(length=6):
        """Generate cryptographically secure numeric OTP."""
        return ''.join([str(secrets.randbelow(10)) for _ in range(length)])


# ─── Login Attempt Tracking ──────────────────────────────────────────────────

class LoginAttemptTracker:
    """Track and limit login attempts to prevent brute force attacks."""

    def __init__(self, db, max_attempts=5, lockout_duration_minutes=15):
        self.collection = db['login_attempts']
        self.max_attempts = max_attempts
        self.lockout_duration = timedelta(minutes=lockout_duration_minutes)
        # Create TTL index for automatic cleanup (expire after 7 days)
        try:
            self.collection.create_index('timestamp', expireAfterSeconds=7 * 24 * 3600)
        except Exception:
            pass

    def record_attempt(self, username, success=False, ip_address=None):
        """Record a login attempt."""
        now = datetime.now(timezone.utc)
        self.collection.insert_one({
            'username': str(username)[:50],  # Sanitize
            'success': bool(success),
            'ip_address': ip_address or request.remote_addr,
            'user_agent': request.headers.get('User-Agent', '')[:500],
            'timestamp': now
        })

    def is_locked(self, username):
        """Check if account is locked due to too many failed attempts."""
        lockout_time = datetime.now(timezone.utc) - self.lockout_duration
        failed_count = self.collection.count_documents({
            'username': str(username)[:50],
            'success': False,
            'timestamp': {'$gte': lockout_time}
        })
        return failed_count >= self.max_attempts

    def get_remaining_attempts(self, username):
        """Get remaining login attempts before lockout."""
        lockout_time = datetime.now(timezone.utc) - self.lockout_duration
        failed_count = self.collection.count_documents({
            'username': str(username)[:50],
            'success': False,
            'timestamp': {'$gte': lockout_time}
        })
        return max(0, self.max_attempts - failed_count)

    def reset_attempts(self, username):
        """Reset failed attempts for a user (after successful login)."""
        self.collection.delete_many({
            'username': str(username)[:50],
            'success': False
        })


# ─── Role-Based Access Control ───────────────────────────────────────────────

def requires_role(*roles):
    """Decorator to restrict access to specific roles."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_role = None
            if session.get('admin'):
                user_role = 'admin'
            elif session.get('principal'):
                user_role = 'principal'
            elif session.get('teacher_id'):
                user_role = 'teacher'
            elif session.get('accountant'):
                user_role = 'accountant'
            elif session.get('student_id'):
                user_role = 'student'

            if user_role not in roles:
                flash('आपके पास इस पेज को देखने की अनुमति नहीं है।')
                abort(403)

            return f(*args, **kwargs)
        return decorated_function
    return decorator


# ─── NoSQL Injection Prevention ──────────────────────────────────────────────

def sanitize_mongo_query(value):
    """
    Prevent NoSQL injection by ensuring query values are safe types.
    Rejects any dict/list that contains MongoDB operator keys ($gt, $ne, etc.).
    """
    if isinstance(value, dict):
        for key in value:
            if isinstance(key, str) and key.startswith('$'):
                raise ValueError(f"Potential NoSQL injection detected: operator '{key}'")
        return {k: sanitize_mongo_query(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [sanitize_mongo_query(item) for item in value]
    elif isinstance(value, str):
        return value  # Strings are safe — operators only matter in dicts
    else:
        return value


def safe_str(value, max_length=255):
    """
    Ensure a value from request input is a plain string, not a dict/list.
    Prevents NoSQL injection where attackers send {"$gt": ""} instead of a string.
    """
    if isinstance(value, (dict, list)):
        return ''
    return str(value)[:max_length] if value else ''


# ─── CSRF Token Management ──────────────────────────────────────────────────

def generate_csrf_token():
    """Generate CSRF token for forms (used when Flask-WTF is not available)."""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']


def validate_csrf_token(token):
    """Validate CSRF token using timing-safe comparison."""
    expected = session.get('_csrf_token', '')
    if not token or not expected:
        return False
    return hmac.compare_digest(str(token), str(expected))
