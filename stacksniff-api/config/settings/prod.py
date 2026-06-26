from config.settings.base import *  # noqa: F403, F401

DEBUG = False

# Ensure ALLOWED_HOSTS is defined in production
if not ALLOWED_HOSTS:
    raise ValueError("ALLOWED_HOSTS must be set in production via environment variable.")

REST_FRAMEWORK = {
    **REST_FRAMEWORK,
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
}

# Production security headers
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SECURE_SSL_REDIRECT = env.bool("SECURE_SSL_REDIRECT", default=True)
SESSION_COOKIE_SECURE = env.bool("SESSION_COOKIE_SECURE", default=True)
CSRF_COOKIE_SECURE = env.bool("CSRF_COOKIE_SECURE", default=True)

# ---------------------------------------------------------------------------
# Database — PostgreSQL required for production.
# NOTE: SQLite serialises all writes behind a single file lock; it cannot
#       support concurrent API requests.  Set DATABASE_URL or DB_* env vars.
#
# CONN_MAX_AGE=60 keeps connections alive across requests (connection pooling
# at the Django layer, one persistent connection per uvicorn worker thread).
# ---------------------------------------------------------------------------
_db_url = env.str("DATABASE_URL", default="")
if _db_url.startswith("postgres"):
    _db_config = env.db("DATABASE_URL")
    _db_config["CONN_MAX_AGE"] = env.int("DB_CONN_MAX_AGE", default=60)
    _db_config.setdefault("OPTIONS", {})
    _db_config["OPTIONS"].setdefault("connect_timeout", 10)
    DATABASES = {"default": _db_config}
# If DATABASE_URL is not a postgres URL, base.py SQLite default is kept.
# Change DATABASE_URL to a postgres:// URI before going to production.
