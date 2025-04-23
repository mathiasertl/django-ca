# Install PostgreSQL
apt-get install -y postgresql

# Make sure that PostgreSQL listens on all interfaces
echo "listen_addresses = '*'" > /etc/postgresql/14/main/conf.d/django-ca.conf

# Allow connections from backend and frontend container
echo "
# Allow connections for django-ca
# TYPE  DATABASE        USER            ADDRESS                 METHOD
host    django_ca       django_ca       192.168.56.13/32        md5
host    django_ca       django_ca       192.168.56.14/32        md5
" >> /etc/postgresql/14/main/pg_hba.conf

# Restart PostgreSQL for changes to take effect
systemctl restart postgresql

# Create database and user
sudo -u postgres psql <<EOF
CREATE DATABASE django_ca;
CREATE USER django_ca WITH ENCRYPTED PASSWORD 'db-password';
GRANT ALL PRIVILEGES ON DATABASE django_ca TO django_ca;
EOF