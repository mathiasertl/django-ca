"""Test settings for the django-ca project."""

import json
import os
import sys

import packaging.version

import cryptography

import django
from django.core.exceptions import ImproperlyConfigured

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT_DIR = os.path.dirname(BASE_DIR)
DOC_DIR = os.path.join(ROOT_DIR, "docs", "source")
FIXTURES_DIR = os.path.join(BASE_DIR, "django_ca", "tests", "fixtures")

DEBUG = False

ADMINS = (
    # ('Your Name', 'your_email@example.com'),
)


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

# If you set this to False, Django will not format dates, numbers and
# calendars according to the current locale.
USE_L10N = True

# If you set this to False, Django will not use timezone-aware datetimes.
USE_TZ = False

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

# List of finder classes that know how to find static files in
# various locations.
STATICFILES_FINDERS = (
    "django.contrib.staticfiles.finders.FileSystemFinder",
    "django.contrib.staticfiles.finders.AppDirectoriesFinder",
    # 'django.contrib.staticfiles.finders.DefaultStorageFinder',
)

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
# performed by this configuration is to send an email to
# the site admins on every HTTP 500 error when DEBUG=False.
# See http://docs.djangoproject.com/en/dev/topics/logging for
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

# Fixture data used by test cases
with open(os.path.join(FIXTURES_DIR, "cert-data.json")) as stream:
    _fixture_data = json.load(stream)

# Custom settings
CA_DEFAULT_SUBJECT = {
    "C": "AT",
    "ST": "Vienna",
    "L": "Vienna",
    "O": "Django CA",
    "OU": "Django CA Testsuite",
}
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
    "ecc": {
        "ca": _fixture_data["certs"]["ecc"]["serial"],
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

# Newest versions of software components.
# NOTE: These values are validated by various release scripts
NEWEST_PYTHON_VERSION = (3, 10)
NEWEST_CRYPTOGRAPHY_VERSION = (36, 0)
NEWEST_DJANGO_VERSION = (4, 0)

# Determine if we're running on the respective newest versions
_parsed_cg_version = packaging.version.parse(cryptography.__version__).release
CRYPTOGRAPHY_VERSION = _parsed_cg_version[:2]  # type: ignore[index]
NEWEST_PYTHON = sys.version_info[0:2] == NEWEST_PYTHON_VERSION
NEWEST_CRYPTOGRAPHY = CRYPTOGRAPHY_VERSION == NEWEST_CRYPTOGRAPHY_VERSION
NEWEST_DJANGO = django.VERSION[:2] == NEWEST_DJANGO_VERSION
NEWEST_VERSIONS = NEWEST_PYTHON and NEWEST_CRYPTOGRAPHY and NEWEST_DJANGO

# For Selenium test cases
SKIP_SELENIUM_TESTS = (
    os.environ.get("SKIP_SELENIUM_TESTS", "n" if (NEWEST_PYTHON and NEWEST_CRYPTOGRAPHY) else "y")
    .lower()
    .strip()
    == "y"
)

# Set COLUMNS, which is used by argparse to determine the terminal width. If this is not set, the output of
# some argparse commands depend on the terminal size.
os.environ["COLUMNS"] = "80"

VIRTUAL_DISPLAY = os.environ.get("VIRTUAL_DISPLAY", "y").lower().strip() == "y"
if "GECKOWEBDRIVER" in os.environ:
    GECKODRIVER_PATH = os.path.join(os.environ["GECKOWEBDRIVER"], "geckodriver")
else:
    GECKODRIVER_PATH = os.path.join(ROOT_DIR, "contrib", "selenium", "geckodriver")
if "TOX_ENV_DIR" in os.environ:
    GECKODRIVER_LOG_PATH = os.path.join(os.environ["TOX_ENV_DIR"], "geckodriver.log")
else:
    GECKODRIVER_LOG_PATH = os.path.join(ROOT_DIR, "geckodriver.log")

if not os.path.exists(GECKODRIVER_PATH) and not SKIP_SELENIUM_TESTS:
    raise ImproperlyConfigured(
        "Please download geckodriver to %s: "
        "https://selenium-python.readthedocs.io/installation.html#drivers" % GECKODRIVER_PATH
    )

CA_USE_CELERY = False

CA_PASSWORDS = {
    _fixture_data["certs"]["pwd"]["serial"]: _fixture_data["certs"]["pwd"]["password"].encode("utf-8"),
}
