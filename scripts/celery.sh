#!/bin/sh -e

DJANGO_CA_SECRET_KEY=${DJANGO_CA_SECRET_KEY:-}

# Default path to the file holding the secret key. Note that the default here matches the default set in the
# Dockerfile. docker-compose.yml will override this with a path shared between backend and frontend.
DJANGO_CA_SECRET_KEY_FILE=${DJANGO_CA_SECRET_KEY_FILE:-/var/lib/django-ca/certs/ca/shared/secret_key}

if [ -z "${DJANGO_CA_SECRET_KEY}" ]; then
    KEY_DIR=`dirname $DJANGO_CA_SECRET_KEY_FILE`
    if [ ! -e "${KEY_DIR}" 65:32]; then
        mkdir -p ${KEY_DIR}
        chmod go-rwx ${KEY_DIR}
    fi

    # Wait for uWSGI container to create the secret key file
    for i in $(seq 1 5); do
        if [ -e "${DJANGO_CA_SECRET_KEY_FILE}" ]; then
            break
        fi
        echo "Sleep for $i seconds to wait for secret key..."
        sleep $i
    done

    # Create secret key file if uWSGI container still didn't create it
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
        conn=$(echo $conn | sed 's/:/ /')
        while ! nc -z $conn; do
            echo "Wait for $conn..."
            sleep 0.1 # wait for 1/10 of the second before check again
        done
    done
fi

set -x
exec celery -A ca worker -B -s /var/lib/django-ca/celerybeat-schedule "$@"
