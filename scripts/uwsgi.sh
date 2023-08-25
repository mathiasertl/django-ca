#!/bin/sh -e

DJANGO_CA_UWSGI_INI=${DJANGO_CA_UWSGI_INI:-/usr/src/django-ca/uwsgi/uwsgi.ini}
DJANGO_CA_UWSGI_PARAMS=${DJANGO_CA_UWSGI_PARAMS:-}
DJANGO_CA_LIB_DIR=${DJANGO_CA_LIB_DIR:-/var/lib/django-ca}

if [ ! -e ${DJANGO_CA_UWSGI_INI} ]; then
    echo "${DJANGO_CA_UWSGI_INI}: No such file or directory."
    exit 1
fi

DJANGO_CA_SECRET_KEY=${DJANGO_CA_SECRET_KEY:-}
DJANGO_CA_SECRET_KEY_FILE=${DJANGO_CA_SECRET_KEY_FILE:-/var/lib/django-ca/certs/ca/shared/secret_key}

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

# Synchronize NGINX configuration to ${NGINX_TEMPLATES_DIR} (used by Docker Compose to update configuration).
if [ -n "${NGINX_TEMPLATE}" ]; then
    # This directory is a Docker volume mapped to /etc/nginx/templates/ in Docker Compose
    NGINX_TEMPLATE_DIR=/var/lib/django-ca/nginx/templates/

    NGINX_TEMPLATE_SOURCE="/usr/src/django-ca/nginx/${NGINX_TEMPLATE}.template"

    if [ -r "${NGINX_TEMPLATE_SOURCE}" ]; then
        mkdir -p ${NGINX_TEMPLATE_DIR}/include.d/
        cp -pf "${NGINX_TEMPLATE_SOURCE}" ${NGINX_TEMPLATE_DIR}default.conf.template
        cp -pf /usr/src/django-ca/nginx/include.d/*.conf ${NGINX_TEMPLATE_DIR}/include.d/
        cp -pf /usr/src/django-ca/nginx/include.d/*.conf.template ${NGINX_TEMPLATE_DIR}/include.d/
    else
        echo "${NGINX_TEMPLATE}: NGINX template not found."
        exit 1
    fi
fi

# Wait for connections to be up (in this case the database), as the subsequent commands require access to it
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
