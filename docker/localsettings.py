import os

from django.utils.crypto import get_random_string

DEBUG = False
LOGIN_URL = '/admin/login/'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': '/var/lib/django-ca/db.sqlite3',
    },
}
STATIC_ROOT = '/usr/share/django-ca/'
ALLOWED_HOSTS = [
    '*'
]

# We generate SECRET_KEY on first invocation
_secret_key_path = '/var/lib/django-ca/secret_key'
if os.path.exists(_secret_key_path):
    with open(_secret_key_path) as stream:
        SECRET_KEY = stream.read()
    print('Read secret key: %s' % SECRET_KEY)
else:
    SECRET_KEY = get_random_string(length=32)
    with open(_secret_key_path, 'w') as stream:
        stream.write(SECRET_KEY)
    print('Generated secret key: %s' % SECRET_KEY)
