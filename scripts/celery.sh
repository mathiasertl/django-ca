#!/bin/sh -e

echo "celery.sh is deprecated and will be removed in django-ca==4.0.0, use django-ca-celery instead." 1>&2
exec /usr/src/django-ca/scripts/django-ca-celery.py "$@"
