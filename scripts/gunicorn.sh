#!/bin/sh -e

echo "gunicorn.sh is deprecated and will be removed in django-ca==4.0.0, use django-ca-gunicorn instead." 1>&2
exec /usr/src/django-ca/scripts/django-ca-gunicorn.py "$@"
