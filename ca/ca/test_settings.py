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

"""Test settings for the django-ca project."""

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from django.utils.crypto import get_random_string

from ca.settings_utils import UrlPatternsModel

# Base paths in this project
BASE_DIR = Path(__file__).resolve().parent.parent  # ca/

DEBUG = False

ADMINS = (
    # ('Your Name', 'your_email@example.com'),
)


if _postgres_host := os.environ.get("POSTGRES_HOST"):
    DATABASE_BACKEND = "postgres"
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "HOST": _postgres_host,
            "PORT": int(os.environ.get("POSTGRES_PORT", "5432")),
            "NAME": os.environ.get("POSTGRES_DB", "postgres"),
            "USER": os.environ.get("POSTGRES_USER", "postgres"),
            "PASSWORD": os.environ.get("POSTGRES_PASSWORD", "django-ca-test-password"),
        },
    }
elif _mariadb_host := os.environ.get("MARIADB_HOST"):
    DATABASE_BACKEND = "mariadb"
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.mysql",
            "HOST": _mariadb_host,
            "PORT": int(os.environ.get("MARIADB_PORT", "3306")),
            "NAME": os.environ.get("MARIADB_DATABASE", "django_ca"),
            "USER": os.environ.get("MARIADB_USER", "root"),
            "PASSWORD": os.environ.get("MARIADB_PASSWORD", "django-ca-test-password"),
        },
    }
else:
    DATABASE_BACKEND = "sqlite"
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": ":memory:",
        },
    }
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Hosts/domain names that are valid for this site; required if DEBUG is False
# See https://docs.djangoproject.com/en/1.5/ref/settings/#allowed-hosts
# NOTE: 'testserver' is always added by Django itself
ALLOWED_HOSTS = [
    "localhost",
    "example.com",
]

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# In a Windows environment this must be set to your system time zone.
TIME_ZONE = "Etc/UTC"

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


STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
    },
    "django-ca": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
        "OPTIONS": {
            "location": "/does/not/exist/django-ca",
            "file_permissions_mode": 0o600,
            "directory_permissions_mode": 0o700,
        },
    },
    "secondary": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
        "OPTIONS": {
            "location": "/does/not/exist/secondary",
            "file_permissions_mode": 0o600,
            "directory_permissions_mode": 0o700,
        },
    },
}

# Speeds up tests that create a Django user
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.MD5PasswordHasher",
]

# Make this unique, and don't share it with anybody.
SECRET_KEY = "fake-key"
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

INSTALLED_APPS = (
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.admin",
    # Uncomment the next line to enable admin documentation:
    # 'django.contrib.admindocs',
    "django_object_actions",
    "django_ca",
    "ninja",
)

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "debug": True,
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
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {"require_debug_false": {"()": "django.utils.log.RequireDebugFalse"}},
    "handlers": {
        "console": {
            "class": "logging.NullHandler",
        },
    },
    "loggers": {
        "django.request": {
            "handlers": ["console"],
            "level": "ERROR",
            "propagate": False,
        },
    },
}

# Load fixture data in settings as well. We cannot load it from django_ca.tests.base.constants, as that would
# import the parent modules, which at present also "from django.conf import settings", which causes a circular
# import situation.
with open(BASE_DIR / "django_ca" / "tests" / "fixtures" / "cert-data.json", encoding="utf-8") as stream:
    _fixture_data = json.load(stream)


# PKCS11 settings
_timestamp = datetime.now(tz=UTC).strftime("%Y%m%d%H%M%S")
PKCS11_PATH = os.environ.get("PKCS11_LIBRARY", "/usr/lib/softhsm/libsofthsm2.so")
PKCS11_TOKEN_LABEL = f"pytest.{_timestamp}.{get_random_string(8)}"
PKCS11_SO_PIN = "so-pin-1234"
PKCS11_USER_PIN = "user-pin-1234"

# Some environments do not support all key algorithms:
# * Alpine 3.20 does not support ed448 for unknown reasons.
PKCS11_EXCLUDE_KEY_TYPES = os.environ.get("PKCS11_EXCLUDE_KEY_TYPES", "").split(",")
PKCS11_EXCLUDE_ELLIPTIC_CURVES = os.environ.get("PKCS11_EXCLUDE_ELLIPTIC_CURVES", "").split(",")


CA_KEY_BACKENDS = {
    "default": {
        "BACKEND": "django_ca.key_backends.storages.StoragesBackend",
        "OPTIONS": {"storage_alias": "django-ca"},
    },
    "secondary": {
        "BACKEND": "django_ca.key_backends.storages.StoragesBackend",
        "OPTIONS": {"storage_alias": "secondary"},
    },
    "hsm": {
        "BACKEND": "django_ca.key_backends.hsm.HSMBackend",
        "OPTIONS": {
            "library_path": PKCS11_PATH,
            "token": PKCS11_TOKEN_LABEL,
            "user_pin": PKCS11_USER_PIN,
        },
    },
    "db": {"BACKEND": "django_ca.key_backends.db.DBBackend"},
}

CA_OCSP_KEY_BACKENDS = {
    "default": {
        "BACKEND": "django_ca.key_backends.storages.StoragesOCSPBackend",
        "OPTIONS": {"storage_alias": "django-ca"},
    },
    "hsm": {
        "BACKEND": "django_ca.key_backends.hsm.HSMOCSPBackend",
        "OPTIONS": {
            "library_path": PKCS11_PATH,
            "token": PKCS11_TOKEN_LABEL,
            "user_pin": PKCS11_USER_PIN,
        },
    },
    "db": {"BACKEND": "django_ca.key_backends.db.DBOCSPBackend"},
}

# Custom settings
CA_DEFAULT_SUBJECT = (
    {"oid": "C", "value": "AT"},
    {"oid": "ST", "value": "Vienna"},
    {"oid": "L", "value": "Vienna"},
    {"oid": "O", "value": "Django CA"},
    {"oid": "OU", "value": "Django CA Testsuite"},
)
CA_MIN_KEY_SIZE = 1024
CA_DEFAULT_KEY_SIZE = 1024

# Default expiry is 100 days, note that pre-generated CAs have lifetime of only 365 days
CA_DEFAULT_EXPIRES = 100

# should be something that doesn't exist, so make sure we use a decorator everywhere
CA_DIR = "/non/existent"

# WARNING: do not set to testserver, as URLValidator does not consider it a valid hostname
CA_DEFAULT_HOSTNAME = "localhost:8000"

CA_OCSP_URLS = {
    "root": {
        "ca": _fixture_data["certs"]["root"]["serial"],
        "responder_key": _fixture_data["certs"]["profile-ocsp"]["key_filename"],
        "responder_cert": _fixture_data["certs"]["profile-ocsp"]["pub_filename"],
    },
    "child": {
        "ca": _fixture_data["certs"]["child"]["serial"],
        "responder_key": _fixture_data["certs"]["profile-ocsp"]["key_filename"],
        "responder_cert": _fixture_data["certs"]["profile-ocsp"]["pub_filename"],
    },
    "ec": {
        "ca": _fixture_data["certs"]["ec"]["serial"],
        "responder_key": _fixture_data["certs"]["profile-ocsp"]["key_filename"],
        "responder_cert": _fixture_data["certs"]["profile-ocsp"]["pub_filename"],
    },
    "dsa": {
        "ca": _fixture_data["certs"]["dsa"]["serial"],
        "responder_key": _fixture_data["certs"]["profile-ocsp"]["key_filename"],
        "responder_cert": _fixture_data["certs"]["profile-ocsp"]["pub_filename"],
    },
    "pwd": {
        "ca": _fixture_data["certs"]["pwd"]["serial"],
        "responder_key": _fixture_data["certs"]["profile-ocsp"]["key_filename"],
        "responder_cert": _fixture_data["certs"]["profile-ocsp"]["pub_filename"],
    },
}
CA_ENABLE_ACME = True


CA_USE_CELERY = False
CA_ENABLE_REST_API = True

CA_PASSWORDS = {
    _fixture_data["certs"]["pwd"]["serial"]: _fixture_data["certs"]["pwd"]["password"].encode("utf-8"),
}

EXTEND_URL_PATTERNS = UrlPatternsModel([])
EXTEND_INCLUDED_APPS: list[str] = []
