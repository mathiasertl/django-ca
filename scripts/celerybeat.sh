#!/bin/sh -e

. /usr/src/django-ca/scripts/include.d/functions.sh

create_secret_key
wait_for_connections
run_manage_commands

set -x
exec celery -A ca beat -s /var/lib/django-ca/celerybeat-schedule --pidfile /run/django-ca/celery.pid "$@"
