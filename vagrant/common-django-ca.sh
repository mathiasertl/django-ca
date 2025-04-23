set -ex

mkdir -p /etc/uv
cat > /etc/uv/uv.toml <<EOF
concurrent-downloads = 1
concurrent-builds = 1
concurrent-installs = 1
EOF

CA_DEFAULT_HOSTNAME="${CA_DEFAULT_HOSTNAME:-localhost}"
export CA_DEFAULT_HOSTNAME

apt-get install -y build-essential clang python3 python3-venv python3-dev postgresql-client libpq-dev

# Install uv if requested
if [ "$USE_UV" = "1" ]; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
  source "$HOME/.local/bin/env"
fi

mkdir -p /opt/django-ca/src/ /etc/django-ca/
adduser --system --group --disabled-login --home=/opt/django-ca/home/ django-ca

# Extract source code
cd /vagrant
git archive --format=tar "--prefix=django-ca-$DJANGO_CA_VERSION/" HEAD | (cd /opt/django-ca/src/ && tar xf -)

# Create version-agnostic symlink
ln -s "/opt/django-ca/src/django-ca-$DJANGO_CA_VERSION" "${INSTALL_BASE}"

# Copy common SystemD and application configuration
ln -s /opt/django-ca/src/django-ca/systemd/systemd.conf /etc/django-ca/
envsubst < /vagrant/vagrant/config/00-base.yaml > /etc/django-ca/00-base.yaml

# Create virtualenv
cd "${INSTALL_BASE}"
if [ "$USE_UV" = "1" ]; then
  UV_PYTHON_INSTALL_DIR=/opt/django-ca/python/ uv venv --managed-python

  # Install python-pkcs11 and psycopg separately to prevent parallel builds and thus OOM errors.
  # NOTE: concurrent-* settings seem to have no effect (also tried env variables).
  uv pip install python-pkcs11
  uv pip install "psycopg[c]"

  SETUPTOOLS_SCM_PRETEND_VERSION_FOR_DJANGO_CA=$DJANGO_CA_VERSION uv sync --no-default-groups --all-extras --no-extra mysql
else
  python3 -m venv .venv/
  .venv/bin/pip install -U pip setuptools wheel setuptools-scm
  SETUPTOOLS_SCM_PRETEND_VERSION_FOR_DJANGO_CA=$DJANGO_CA_VERSION .venv/bin/pip install -e ".[api,celery,hsm,postgres,redis,yaml]"
fi

# Setup manage.py shortcut
ln -s "${INSTALL_BASE}/conf/source/manage" /usr/local/bin/django-ca