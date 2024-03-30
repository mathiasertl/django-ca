# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca. If not, see
# <http://www.gnu.org/licenses/>.

"""Default settings for the django-ca Django project."""

import os
from pathlib import Path

from ca.settings_utils import (
    load_secret_key,
    load_settings_from_environment,
    load_settings_from_files,
    update_database_setting_from_environment,
)

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = Path(__file__).resolve().parent.parent  # ca/

DEBUG = False

ADMINS = (
    # ('Your Name', 'your_email@example.com'),
)

if os.environ.get("SQLITE_NAME"):
    db_file = os.environ.get("SQLITE_NAME")
else:
    db_file = os.path.join(BASE_DIR, "db.sqlite3")


DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": db_file,
    }
}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Hosts/domain names that are valid for this site; required if DEBUG is False
# See https://docs.djangoproject.com/en/1.5/ref/settings/#allowed-hosts
ALLOWED_HOSTS: list[str] = []

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# In a Windows environment this must be set to your system time zone.
TIME_ZONE = "Europe/Vienna"

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = "en-us"

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = True

# If you set this to False, Django will not use timezone-aware datetimes.
USE_TZ = True

# Absolute filesystem path to the directory that will hold user-uploaded files.
# Example: "/var/www/example.com/media/"
MEDIA_ROOT = ""

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash.
# Examples: "http://example.com/media/", "http://media.example.com/"
MEDIA_URL = ""

# Absolute path to the directory static files should be collected to.
# Don't put anything in this directory yourself; store your static files
# in apps' "static/" subdirectories and in STATICFILES_DIRS.
# Example: "/var/www/example.com/static/"
STATIC_ROOT = ""

# URL prefix for static files.
# Example: "http://example.com/static/", "http://static.example.com/"
STATIC_URL = "/static/"

# Additional locations of static files
STATICFILES_DIRS = (
    # Put strings here, like "/home/html/static" or "C:/www/django/static".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
)

# Default file storage configuration
STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
    },
}

# Configure storage for certificate authorities
CA_DEFAULT_STORAGE_ALIAS = "django-ca"
CA_DIR = None

# List of finder classes that know how to find static files in
# various locations.
STATICFILES_FINDERS = (
    "django.contrib.staticfiles.finders.FileSystemFinder",
    "django.contrib.staticfiles.finders.AppDirectoriesFinder",
)

# Make this unique, and don't share it with anybody.
SECRET_KEY = os.environ.get("DJANGO_CA_SECRET_KEY", "")
SECRET_KEY_FILE = ""

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

ROOT_URLCONF = "ca.urls"

# Python dotted path to the WSGI application used by Django's runserver.
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
]
CA_CUSTOM_APPS: list[str] = []
CA_DEFAULT_HOSTNAME = None
CA_URL_PATH = "django_ca/"
CA_ENABLE_REST_API = False

# Setting to allow us to disable clickjacking projection if header is already set by the webserver
CA_ENABLE_CLICKJACKING_PROTECTION = True

# Enable the admin interface
ENABLE_ADMIN = True

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

# A sample logging configuration. The only tangible logging
# performed by this configuration is to email the site admins
# on every HTTP 500 error when DEBUG=False. See
#   http://docs.djangoproject.com/en/dev/topics/logging for
# more details on how to customize your logging configuration.
LOGGING = None
LOG_FORMAT = "[%(levelname)-8s %(asctime).19s] %(message)s"
LOG_LEVEL = "WARNING"
LIBRARY_LOG_LEVEL = "WARNING"

# Silence some HTTPS related Django checks by default as certificate authorities need to serve some URLs
# (OCSP, CRL) via unencrypted HTTP. HSTS headers and SSL redirects should be handled by the HTTP server (e.g.
# nginx) in front of the Django application server (e.g. uWSGI).
# NOTE: Also update conf/compose/10-docker-compose.yaml if you update this setting.
SILENCED_SYSTEM_CHECKS = [
    "security.W004",  # no SECURE_HSTS_SECONDS setting
    "security.W008",  # no SECURE_SSL_REDIRECT setting
]

_skip_local_config = os.environ.get("DJANGO_CA_SKIP_LOCAL_CONFIG") == "1"

# Secure CSRF cookie
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = True

# Celery configuration
CELERY_BEAT_SCHEDULE = {
    "cache-crls": {
        "task": "django_ca.tasks.cache_crls",
        "schedule": 86100,
    },
    "generate-ocsp-keys": {
        # Attempt to regenerate OCSP responder certificates every hour. Certificates are only regenerated if
        # they expire in the near future.
        "task": "django_ca.tasks.generate_ocsp_keys",
        "schedule": 3600,
    },
    "acme-cleanup": {
        # ACME cleanup runs once a day
        "task": "django_ca.tasks.acme_cleanup",
        "schedule": 86400,
    },
}

# Load settings from files
for _setting, _value in load_settings_from_files(BASE_DIR):
    globals()[_setting] = _value

# Load settings from environment variables
for _setting, _value in load_settings_from_environment():
    globals()[_setting] = _value

# Try to use POSTGRES_* and MYSQL_* environment variables to determine database access credentials.
# These are the variables set by the standard PostgreSQL/MySQL Docker containers.
update_database_setting_from_environment(DATABASES)

# Load SECRET_KEY from a file if not already defined.
# NOTE: This must be called AFTER load_settings_from_environment(), as this might set SECRET_KEY_FILE in the
#       first place.
SECRET_KEY = load_secret_key(SECRET_KEY, SECRET_KEY_FILE)

if CA_ENABLE_CLICKJACKING_PROTECTION is True:
    if "django.middleware.clickjacking.XFrameOptionsMiddleware" not in MIDDLEWARE:
        MIDDLEWARE.append("django.middleware.clickjacking.XFrameOptionsMiddleware")

# Set ALLOWED_HOSTS to CA_DEFAULT_HOSTNAME if the former is not yet defined but the latter isn't
if not ALLOWED_HOSTS and CA_DEFAULT_HOSTNAME:
    ALLOWED_HOSTS = [CA_DEFAULT_HOSTNAME]

# Remove django.contrib.admin if the admin interface is not enabled.
if ENABLE_ADMIN is not True and "django.contrib.admin" in INSTALLED_APPS:
    INSTALLED_APPS.remove("django.contrib.admin")

INSTALLED_APPS = INSTALLED_APPS + CA_CUSTOM_APPS
if CA_ENABLE_REST_API and "ninja" not in INSTALLED_APPS:
    INSTALLED_APPS.append("ninja")

if STORAGES is None:
    # Set the default storages argument
    STORAGES = {
        "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
        "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
    }

if CA_DEFAULT_STORAGE_ALIAS not in STORAGES:
    if CA_DIR is None:
        CA_DIR = os.path.join(BASE_DIR, "files")

    STORAGES[CA_DEFAULT_STORAGE_ALIAS] = {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
        "OPTIONS": {  # type: ignore[dict-item]  # django-stubs seems to have an issue here
            "location": CA_DIR,
            "file_permissions_mode": 0o600,
            "directory_permissions_mode": 0o700,
        },
    }

if LOGGING is None:
    LOGGING = {
        "version": 1,
        "disable_existing_loggers": False,
        "filters": {
            "require_debug_false": {
                "()": "django.utils.log.RequireDebugFalse",
            }
        },
        "formatters": {
            "main": {
                "format": LOG_FORMAT,
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "main",
            },
            "mail_admins": {
                "level": "ERROR",
                "filters": ["require_debug_false"],
                "class": "django.utils.log.AdminEmailHandler",
            },
        },
        "loggers": {
            "django_ca": {
                "handlers": ["console"],
                "level": LOG_LEVEL,
                "propagate": False,
            },
            "django.request": {
                "handlers": ["mail_admins"],
                "level": "ERROR",
                "propagate": True,
            },
        },
        "root": {
            "handlers": ["console"],
            "level": LIBRARY_LOG_LEVEL,
        },
    }
