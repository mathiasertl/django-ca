#!/bin/sh -e

. /usr/src/django-ca/scripts/include.d/functions.sh

DJANGO_CA_UWSGI_INI=${DJANGO_CA_UWSGI_INI:-/usr/src/django-ca/uwsgi/uwsgi.ini}
DJANGO_CA_UWSGI_PARAMS=${DJANGO_CA_UWSGI_PARAMS:-}
DJANGO_CA_LIB_DIR=${DJANGO_CA_LIB_DIR:-/var/lib/django-ca}

if [ ! -e ${DJANGO_CA_UWSGI_INI} ]; then
    echo "${DJANGO_CA_UWSGI_INI}: No such file or directory."
    exit 1
fi

# Synchronize NGINX configuration to ${NGINX_TEMPLATES_DIR} (used by Docker Compose to update configuration).
if [ -n "${NGINX_TEMPLATE}" ]; then
    # This directory is a Docker volume mapped to /etc/nginx/templates/ in Docker Compose
    NGINX_TEMPLATE_DIR=/var/lib/django-ca/nginx/templates/

    NGINX_TEMPLATE_SOURCE_DIR="/usr/src/django-ca/nginx/"
    NGINX_TEMPLATE_SOURCE="${NGINX_TEMPLATE_SOURCE_DIR}${NGINX_TEMPLATE}.template"

    if [ -r "${NGINX_TEMPLATE_SOURCE}" ]; then
        mkdir -p "${NGINX_TEMPLATE_DIR}/include.d/"
        cp -pf "${NGINX_TEMPLATE_SOURCE}" "${NGINX_TEMPLATE_DIR}default.conf.template"
        cp -pf ${NGINX_TEMPLATE_SOURCE_DIR}include.d/*.conf "${NGINX_TEMPLATE_DIR}/include.d/"
        cp -pf ${NGINX_TEMPLATE_SOURCE_DIR}include.d/*.conf.template "${NGINX_TEMPLATE_DIR}/include.d/"

        # Include http/https directories if they exist. This allows specialized containers to add
        # their own nginx configuration.
        if [ -d "${NGINX_TEMPLATE_SOURCE_DIR}include.d/http" ]; then
          mkdir -p "${NGINX_TEMPLATE_DIR}/include.d/http"
          cp -rf ${NGINX_TEMPLATE_SOURCE_DIR}include.d/http/* "${NGINX_TEMPLATE_DIR}/include.d/http/"
        fi

        if [ -d "${NGINX_TEMPLATE_SOURCE_DIR}include.d/https" ]; then
          mkdir -p "${NGINX_TEMPLATE_DIR}/include.d/https"
          cp -rf ${NGINX_TEMPLATE_SOURCE_DIR}include.d/https/* "${NGINX_TEMPLATE_DIR}/include.d/https/"
        fi
    else
        echo "${NGINX_TEMPLATE}: NGINX template not found."
        exit 1
    fi
fi

create_secret_key
wait_for_connections
run_manage_commands

set -x
uwsgi --ini ${DJANGO_CA_UWSGI_INI} ${DJANGO_CA_UWSGI_PARAMS} "$@"
