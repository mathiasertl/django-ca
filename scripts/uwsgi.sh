#!/bin/sh -e

DJANGO_CA_UWSGI_INI=${DJANGO_CA_UWSGI_INI:-/usr/src/django-ca/uwsgi/uwsgi.ini}
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

key = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(64))
with open('${DJANGO_CA_SECRET_KEY_FILE}', 'w') as stream:
    stream.write(key)
EOF
    fi
    chmod go-rwx ${DJANGO_CA_SECRET_KEY_FILE}

    # Export DJANGO_CA_SECRET_KEY_FILE so that django-ca itself will pick it up.
    export DJANGO_CA_SECRET_KEY_FILE
else
    export DJANGO_CA_SECRET_KEY
fi

if [ -n "${WAIT_FOR_CONNECTIONS}" ]; then
    for conn in ${WAIT_FOR_CONNECTIONS}; do
        conn=${conn/:/ }
        while ! nc -z $conn; do
            echo "Wait for $conn..."
            sleep 0.1 # wait for 1/10 of the second before check again
        done
    done
fi

set -x
python manage.py check --deploy
python manage.py migrate --noinput
python manage.py collectstatic --no-input &
python manage.py cache_crls &
python manage.py regenerate_ocsp_keys &
uwsgi --ini ${DJANGO_CA_UWSGI_INI} ${DJANGO_CA_UWSGI_PARAMS} "$@"
