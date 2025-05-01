set -ex

CA_DEFAULT_HOSTNAME=${CA_DEFAULT_HOSTNAME:-localhost}
export CA_DEFAULT_HOSTNAME

# Install dependencies only required on the frontend service
apt-get install -y nginx

# Create virtualenv
cd "${INSTALL_BASE}"
if [ "$USE_UV" = "1" ]; then
  UV_PYTHON_INSTALL_DIR=/opt/django-ca/python/ uv venv --managed-python

  # Install python-pkcs11 and psycopg separately to prevent parallel builds and thus OOM errors.
  # NOTE: concurrent-* settings seem to have no effect (also tried env variables).
  uv pip install python-pkcs11
  uv pip install "psycopg[c]"

  # CC and LIBRARY_PATH required to compile uWSGI.
  CC=gcc LIBRARY_PATH=/opt/django-ca/python/cpython-3.13.3-linux-x86_64-gnu/lib/ \
  SETUPTOOLS_SCM_PRETEND_VERSION_FOR_DJANGO_CA=$DJANGO_CA_VERSION \
    uv sync --no-default-groups --group uwsgi --all-extras --no-extra mysql --no-extra hsm
else
  python3 -m venv .venv/
  .venv/bin/pip install -U pip setuptools wheel setuptools-scm
  CC=gcc LIBRARY_PATH=/opt/django-ca/python/cpython-3.13.3-linux-x86_64-gnu/lib/ \
  SETUPTOOLS_SCM_PRETEND_VERSION_FOR_DJANGO_CA=$DJANGO_CA_VERSION \
    .venv/bin/pip install -e ".[api,celery,postgres,redis,yaml]" --group uwsgi
fi


# Add django-ca user to the www-data group, so that it can set permissions to the socket
adduser django-ca www-data

# Set up SystemD (Note: SystemD configuration is already copied in common-django-ca.sh)
ln -s "${INSTALL_BASE}/systemd/django-ca.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable django-ca

# Finally start services
systemctl start django-ca

# Collect static files
mkdir -p /opt/django-ca/www/static/
FORCE_USER=root django-ca collectstatic --noinput

# Create a self-signed certificate for nginx
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout "/etc/ssl/${CA_DEFAULT_HOSTNAME}.key" \
  -out "/etc/ssl/${CA_DEFAULT_HOSTNAME}.pem" \
  -subj "/CN=${CA_DEFAULT_HOSTNAME}" \
  -addext "subjectAltName = DNS:${CA_DEFAULT_HOSTNAME}"

# Create DH parameters
mkdir -p /etc/nginx/dhparams/
openssl dhparam -dsaparam -out /etc/nginx/dhparams/dhparam.pem 4096

# Setup NGINX
cat "${INSTALL_BASE}/nginx/source.template" | envsubst > /etc/nginx/sites-available/django-ca.conf
ln -fs /etc/nginx/sites-available/django-ca.conf /etc/nginx/sites-enabled/
nginx -t
systemctl restart nginx