set -ex

CA_DEFAULT_HOSTNAME=${CA_DEFAULT_HOSTNAME:-localhost}
export CA_DEFAULT_HOSTNAME

# Install dependencies only required on the frontend service
apt-get install -y nginx uwsgi uwsgi-plugin-python3

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