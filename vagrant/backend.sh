set -ex

# Create virtualenv
cd "${INSTALL_BASE}"
if [ "$USE_UV" = "1" ]; then
  UV_PYTHON_INSTALL_DIR=/opt/django-ca/python/ uv venv --managed-python

  # Install python-pkcs11 and psycopg separately to prevent parallel builds and thus OOM errors.
  # NOTE: concurrent-* settings seem to have no effect (also tried env variables).
  uv pip install python-pkcs11
  uv pip install "psycopg[c]"

  # CC and LIBRARY_PATH required to compile uWSGI.
  SETUPTOOLS_SCM_PRETEND_VERSION_FOR_DJANGO_CA=$DJANGO_CA_VERSION \
    uv sync --no-default-groups --all-extras --no-extra api --no-extra mysql
else
  python3 -m venv .venv/
  .venv/bin/pip install -U "pip>=25.1" setuptools wheel setuptools-scm
  SETUPTOOLS_SCM_PRETEND_VERSION_FOR_DJANGO_CA=$DJANGO_CA_VERSION \
    .venv/bin/pip install -e ".[celery,hsm,postgres,redis,yaml]"
fi

# Install dependencies only required on the backend service
apt-get install -y softhsm2

# Set up SystemD (Note: SystemD configuration is already copied in common-django-ca.sh)
ln -s /opt/django-ca/src/django-ca/systemd/django-ca-celery.service /etc/systemd/system/
ln -s /opt/django-ca/src/django-ca/systemd/django-ca-celerybeat.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable django-ca-celery django-ca-celerybeat

# Finally start services
systemctl start django-ca-celery
systemctl start django-ca-celerybeat