#!/bin/sh -e

. /usr/src/django-ca/scripts/include.d/functions.sh

create_secret_key
wait_for_connections
run_manage_commands

set -x
exec celery -A ca worker "$@"
