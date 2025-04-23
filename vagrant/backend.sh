set -ex

pwd
ls

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