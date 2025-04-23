# Install RabbitMQ as a message broker.
# Note that RabbitMQ provides more up-to-date packages in their own APT repository:
#   https://www.rabbitmq.com/docs/install-debian#apt-quick-start-cloudsmith
apt-get install -y rabbitmq-server

# Configure permissions for django-ca, see also:
#   https://docs.celeryq.dev/en/stable/getting-started/backends-and-brokers/rabbitmq.html
rabbitmqctl add_user django-ca broker-password
rabbitmqctl add_vhost django-ca
#rabbitmqctl set_user_tags django-ca django-ca
rabbitmqctl set_permissions -p django-ca django-ca ".*" ".*" ".*"