#!/bin/sh -e

DJANGO_CA_UWSGI_INI=${DJANGO_CA_UWSGI_INI:-/usr/src/django-ca/uwsgi/standalone.ini}
DJANGO_CA_UWSGI_PARAMS=${DJANGO_CA_UWSGI_PARAMS:-}
DJANGO_CA_LIB_DIR=${DJANGO_CA_LIB_DIR:-/var/lib/django-ca}

if [ ! -e ${DJANGO_CA_UWSGI_INI} ]; then
    echo "${DJANGO_CA_UWSGI_INI}: No such file or directory."
    exit 1
fi

DJANGO_CA_SECRET_KEY=${DJANGO_CA_SECRET_KEY:-}
DJANGO_CA_SECRET_KEY_FILE=${DJANGO_CA_SECRET_KEY_FILE:-/var/lib/django-ca/secret_key}

if [ -z "${DJANGO_CA_SECRET_KEY}" ]; then
    KEY_DIR=`dirname $DJANGO_CA_SECRET_KEY_FILE`
    if [ ! -e "${KEY_DIR}" ]; then
        mkdir -p ${KEY_DIR}
        chmod go-rwx ${KEY_DIR}
    fi

    if [ ! -e "${DJANGO_CA_SECRET_KEY_FILE}" ]; then
        echo "Create secret key at ${DJANGO_CA_SECRET_KEY_FILE}..."
        python <<EOF
import random, string

key = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(32))
with open('${DJANGO_CA_SECRET_KEY_FILE}', 'w') as stream:
    stream.write(key)
EOF
    fi
    chmod go-rwx ${DJANGO_CA_SECRET_KEY_FILE}
fi

python manage.py migrate --noinput &
uwsgi --ini ${DJANGO_CA_UWSGI_INI} ${DJANGO_CA_UWSGI_PARAMS}
