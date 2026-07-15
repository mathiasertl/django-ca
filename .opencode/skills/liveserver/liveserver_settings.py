"""Settings for running a local live server via manage.py runserver.

Used exclusively for interactive testing by AI agents (and developers). Not for production use.
Start the server with (run from the repo root):

    PYTHONPATH=.opencode/skills/liveserver \
        DJANGO_SETTINGS_MODULE=liveserver_settings \
        uv run python ca/manage.py runserver 127.0.0.1:8001
"""

from pathlib import Path

from ca.settings_utils import UrlPatternsModel

# This file lives at .opencode/skills/liveserver/liveserver_settings.py.
# parents[3] is the repo root; BASE_DIR is ca/ (the Django project root on sys.path).
BASE_DIR = Path(__file__).resolve().parents[3] / "ca"

DEBUG = True

# Insecure key intentionally hard-coded — local testing only, never used in production.
SECRET_KEY = "django-ca-liveserver-insecure-key-for-local-testing-only"

ALLOWED_HOSTS = ["localhost", "127.0.0.1"]

# Persistent SQLite database — survives server restarts. Covered by .gitignore (*.sqlite3).
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "liveserver.sqlite3",
    }
}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

TIME_ZONE = "Europe/Vienna"
LANGUAGE_CODE = "en-us"
USE_I18N = True
USE_TZ = True

MEDIA_ROOT = ""
MEDIA_URL = ""
STATIC_ROOT = ""
STATIC_URL = "/static/"

# CA key/certificate files stored under ca/liveserver_files/ — covered by .gitignore.
_CA_FILES_DIR = BASE_DIR / "liveserver_files"

STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
    "django-ca": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
        "OPTIONS": {
            "location": str(_CA_FILES_DIR),
            "file_permissions_mode": 0o600,
            "directory_permissions_mode": 0o700,
        },
    },
}

CA_DEFAULT_STORAGE_ALIAS = "django-ca"
CA_DIR = "liveserver_files/"

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "ca.urls"
WSGI_APPLICATION = "ca.wsgi.application"

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.admin",
    "django_object_actions",
    "django_ca",
    "ninja",
]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# Cookies do not require HTTPS for local HTTP development server.
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
CSRF_COOKIE_HTTPONLY = False

SILENCED_SYSTEM_CHECKS = [
    "security.W004",  # no SECURE_HSTS_SECONDS
    "security.W008",  # no SECURE_SSL_REDIRECT
    "security.W012",  # SESSION_COOKIE_SECURE = False
    "security.W016",  # CSRF_COOKIE_SECURE = False
]

# CA settings
CA_DEFAULT_HOSTNAME = "localhost:8001"
CA_URL_PATH = "django_ca/"
CA_ENABLE_ACME = True
CA_ENABLE_REST_API = True
CA_USE_CELERY = False  # Tasks run synchronously — no Celery worker needed.

CA_MIN_KEY_SIZE = 2048
CA_DEFAULT_KEY_SIZE = 2048
CA_DEFAULT_EXPIRES = 365

CA_DEFAULT_SUBJECT = (
    {"oid": "C", "value": "AT"},
    {"oid": "ST", "value": "Vienna"},
    {"oid": "L", "value": "Vienna"},
    {"oid": "O", "value": "Django CA"},
)

CA_KEY_BACKENDS = {
    "default": {
        "BACKEND": "django_ca.key_backends.storages.StoragesBackend",
        "OPTIONS": {"storage_alias": "django-ca"},
    },
    "db": {"BACKEND": "django_ca.key_backends.db.DBBackend"},
}

CA_OCSP_KEY_BACKENDS = {
    "default": {
        "BACKEND": "django_ca.key_backends.storages.StoragesOCSPBackend",
        "OPTIONS": {"storage_alias": "django-ca"},
    },
    "db": {"BACKEND": "django_ca.key_backends.db.DBOCSPBackend"},
}

EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

EXTEND_URL_PATTERNS = UrlPatternsModel([])

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "main": {"format": "[%(levelname)-8s %(asctime).19s] %(message)s"},
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "main"},
    },
    "loggers": {
        "django_ca": {"handlers": ["console"], "level": "DEBUG", "propagate": False},
    },
    "root": {"handlers": ["console"], "level": "INFO"},
}
