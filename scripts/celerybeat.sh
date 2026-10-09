#!/bin/sh -e

echo "celerybeat.sh is deprecated and will be removed in django-ca==4.0.0, use django-ca-celerybeat instead." 1>&2
exec /usr/src/django-ca/scripts/django-ca-celerybeat.py "$@"
