# Django settings for ca project.

import os

import yaml

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEBUG = False

ADMINS = (
    # ('Your Name', 'your_email@example.com'),
)

if 'TOX_ENV_DIR' in os.environ:
    db_file = os.path.join(os.environ['TOX_ENV_DIR'], 'db.sqlite3')
else:
    db_file = os.path.join(BASE_DIR, 'db.sqlite3')


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': db_file,
    }
}

# Hosts/domain names that are valid for this site; required if DEBUG is False
# See https://docs.djangoproject.com/en/1.5/ref/settings/#allowed-hosts
ALLOWED_HOSTS = []

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# In a Windows environment this must be set to your system time zone.
TIME_ZONE = 'Europe/Vienna'

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'en-us'

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
MEDIA_ROOT = ''

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash.
# Examples: "http://example.com/media/", "http://media.example.com/"
MEDIA_URL = ''

# Absolute path to the directory static files should be collected to.
# Don't put anything in this directory yourself; store your static files
# in apps' "static/" subdirectories and in STATICFILES_DIRS.
# Example: "/var/www/example.com/static/"
STATIC_ROOT = ''

# URL prefix for static files.
# Example: "http://example.com/static/", "http://static.example.com/"
STATIC_URL = '/static/'

# Additional locations of static files
STATICFILES_DIRS = (
    # Put strings here, like "/home/html/static" or "C:/www/django/static".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
)

# List of finder classes that know how to find static files in
# various locations.
STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
    # 'django.contrib.staticfiles.finders.DefaultStorageFinder',
)

# Make this unique, and don't share it with anybody.
SECRET_KEY = ''
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'ca.urls'

# Python dotted path to the WSGI application used by Django's runserver.
WSGI_APPLICATION = 'ca.wsgi.application'

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.admin',
    # Uncomment the next line to enable admin documentation:
    # 'django.contrib.admindocs',
    'django_object_actions',

    'django_ca',
]
CA_CUSTOM_APPS = []

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
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
    'version': 1,
    'disable_existing_loggers': False,
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse',
        }
    },
    'handlers': {
        'mail_admins': {
            'level': 'ERROR',
            'filters': ['require_debug_false'],
            'class': 'django.utils.log.AdminEmailHandler',
        }
    },
    'loggers': {
        'django.request': {
            'handlers': ['mail_admins'],
            'level': 'ERROR',
            'propagate': True,
        },
    }
}

SECRET_KEY_FILE = ''

try:
    try:
        from .localsettings import *  # NOQA
    except ImportError:
        from localsettings import *  # NOQA
except ImportError:
    pass

_CA_SETTINGS_FILE = os.environ.get('DJANGO_CA_SETTINGS', '')
if _CA_SETTINGS_FILE:
    for filename in _CA_SETTINGS_FILE.split(':'):
        with open(filename) as stream:
            data = yaml.load(stream, Loader=Loader)
        for key, value in data.items():
            globals()[key] = value

# Also use DJANGO_CA_ environment variables
for key, value in {k[10:]: v for k, v in os.environ.items() if k.startswith('DJANGO_CA_')}.items():
    if key == 'SETTINGS':  # points to yaml files loaded above
        continue
    globals()[key] = value

if not SECRET_KEY:
    # We generate SECRET_KEY on first invocation
    if not SECRET_KEY_FILE:
        SECRET_KEY_FILE = os.environ.get('SECRET_KEY_FILE', '/var/lib/django-ca/secret_key')

    if SECRET_KEY_FILE and os.path.exists(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE) as stream:
            SECRET_KEY = stream.read()

INSTALLED_APPS = INSTALLED_APPS + CA_CUSTOM_APPS


def _set_db_setting(name, env_name, default=None):
    if DATABASES['default'].get(name):
        return

    if os.environ.get(env_name):
        DATABASES['default'][name] = os.environ[env_name]
    elif os.environ.get('%s_FILE' % env_name):
        with open(os.environ['%s_FILE' % env_name]) as stream:
            DATABASES['default'][name] = stream.read()
    elif default is not None:
        DATABASES['default'][name] = default


# use POSTGRES_* environment variables from the postgres Docker image
if DATABASES['default']['ENGINE'] == 'django.db.backends.postgresql_psycopg2':
    _set_db_setting('PASSWORD', 'POSTGRES_PASSWORD', default='postgres')
    _set_db_setting('USER', 'POSTGRES_USER', default='postgres')
    _set_db_setting('NAME', 'POSTGRES_DB', default=DATABASES['default'].get('USER'))

# use MYSQL_* environment variables from the mysql Docker image
if DATABASES['default']['ENGINE'] == 'django.db.backends.mysql':
    _set_db_setting('PASSWORD', 'MYSQL_PASSWORD')
    _set_db_setting('USER', 'MYSQL_USER')
    _set_db_setting('NAME', 'MYSQL_DATABASE')
