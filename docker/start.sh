#!/bin/sh

DJANGO_CA_UWSGI_INI=${DJANGO_CA_UWSGI_INI:-/usr/src/django-ca/uwsgi/standalone.ini}
DJANGO_CA_UWSGI_PARAMS=${DJANGO_CA_UWSGI_PARAMS:-}
DJANGO_CA_LIB_DIR=${DJANGO_CA_LIB_DIR:-/var/lib/django-ca}

if [ ! -e ${DJANGO_CA_UWSGI_INI} ]; then
    echo "${DJANGO_CA_UWSGI_INI}: No such file or directory."
    exit 1
fi

if [ ! -e ${DJANGO_CA_LIB_DIR} ]; then
    mkdir -p ${DJANGO_CA_LIB_DIR}
fi

chmod go-rwx ${DJANGO_CA_LIB_DIR}
if [ ! -e ${DJANGO_CA_LIB_DIR}/secret_key ]; then
    python <<EOF
import random, string

key = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(32))
with open('/var/lib/django-ca/secret_key', 'w') as stream:
    stream.write(key)
EOF
fi
chmod go-rwx ${DJANGO_CA_LIB_DIR}/secret_key

python ca/manage.py collectstatic --noinput
python ca/manage.py migrate --noinput
uwsgi --ini ${DJANGO_CA_UWSGI_INI} ${DJANGO_CA_UWSGI_PARAMS}
