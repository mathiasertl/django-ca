create_secret_key() {
  if [ -n "${DJANGO_CA_SECRET_KEY}" ]; then
    return
  fi

  # Default path to the file holding the secret key. Note that the default here matches the default set in the
  # Dockerfile. compose.yaml will override this with a path shared between backend and frontend.
  DJANGO_CA_SECRET_KEY_FILE=${DJANGO_CA_SECRET_KEY_FILE:-/var/lib/django-ca/certs/ca/shared/secret_key}

  KEY_DIR=$(dirname "${DJANGO_CA_SECRET_KEY_FILE}")
  if [ ! -e "${KEY_DIR}" ]; then
    mkdir -p "${KEY_DIR}"
    chmod go-rwx "${KEY_DIR}"
  fi

  # Wait for uWSGI container to create the secret key file
  if [ "${DJANGO_CA_STARTUP_WAIT_FOR_SECRET_KEY_FILE}" = "1" ]; then
    echo "${DJANGO_CA_SECRET_KEY_FILE}: Waiting for file to be generated elsewhere..."
    for i in $(seq 1 5); do
      if [ -e "${DJANGO_CA_SECRET_KEY_FILE}" ]; then
        echo "${DJANGO_CA_SECRET_KEY_FILE}: File was generated."
        break
      fi
      echo "${DJANGO_CA_SECRET_KEY_FILE}: Not yet generated, sleeping for $i seconds..."
        sleep "$i"
    done
  fi

  # Create secret key file if uWSGI container still didn't create it
  if [ ! -e "${DJANGO_CA_SECRET_KEY_FILE}" ]; then
    echo "${DJANGO_CA_SECRET_KEY_FILE}: Creating secret key..."
    python <<EOF
import random, string

key = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(64))
with open('${DJANGO_CA_SECRET_KEY_FILE}', 'w') as stream:
  stream.write(key)
EOF
  fi
  chmod go-rwx "${DJANGO_CA_SECRET_KEY_FILE}"

  # Export DJANGO_CA_SECRET_KEY_FILE so that django-ca itself will pick it up.
  export DJANGO_CA_SECRET_KEY_FILE
}

wait_for_connections() {
  if [ -n "${DJANGO_CA_STARTUP_WAIT_FOR_CONNECTIONS}" ]; then
    for conn in ${DJANGO_CA_STARTUP_WAIT_FOR_CONNECTIONS}; do
      conn=${conn//:/ /}
      while ! nc -z $conn; do
        echo "Wait for $conn..."
        sleep 0.1 # wait for 1/10 of the second before check again
      done
    done
  fi
}

run_manage_commands() {
  if [ "${DJANGO_CA_STARTUP_CHECK}" != "0" ]; then
    python manage.py check --deploy
  fi

  if [ "${DJANGO_CA_STARTUP_MIGRATE}" != "0" ]; then
    echo "Running database migrations..."
    python manage.py migrate --noinput
  fi
  if [ "${DJANGO_CA_STARTUP_CACHE_CRLS}" != "0" ]; then
    echo "Caching CRLs..."
    python manage.py cache_crls &
  fi
  if [ "${DJANGO_CA_STARTUP_REGENERATE_OCSP_KEYS}" != "0" ]; then
    echo "Regenerating OCSP keys..."
    python manage.py regenerate_ocsp_keys &
  fi
  if [ "${DJANGO_CA_STARTUP_COLLECTSTATIC}" != "0" ]; then
    echo "Collecting static files..."
    python manage.py collectstatic --no-input &
  fi
}