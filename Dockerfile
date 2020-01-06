# syntax = docker/dockerfile:experimental
ARG IMAGE=python:3.8-alpine3.10

FROM $IMAGE as base
WORKDIR /usr/src/django-ca

RUN --mount=type=cache,target=/etc/apk/cache ls /etc/apk/cache && echo 6 > /dev/null
RUN --mount=type=cache,target=/etc/apk/cache apk -v upgrade
RUN --mount=type=cache,target=/etc/apk/cache apk -v add --update \
        pcre openssl binutils busybox libpq postgresql-client

# Add user (some tests check if it's impossible to write a file)
RUN addgroup -g 9000 -S django-ca && \
    adduser -S -u 9000 -G django-ca django-ca

FROM base as build
RUN --mount=type=cache,target=/etc/apk/cache apk add \
        build-base linux-headers libffi-dev openssl-dev \
        pcre-dev mailcap mariadb-connector-c-dev postgresql-dev
RUN --mount=type=cache,target=/root/.cache/pip pip install -U setuptools pip wheel

COPY requirements.txt ./
COPY requirements/ requirements/
RUN --mount=type=cache,target=/root/.cache/pip pip install --no-warn-script-location --prefix=/install \
    -r requirements/requirements-docker.txt \
    -r requirements/requirements-redis.txt \
    -r requirements/requirements-mysql.txt \
    -r requirements/requirements-postgres.txt

# Finally, copy sources
COPY ca/ ca/

##############
# Test stage #
##############
FROM build as test
COPY --from=build /install /usr/local
ENV SKIP_SELENIUM_TESTS=y

# Install additional requirements for testing:
RUN --mount=type=cache,target=/root/.cache/pip pip install \
    -r requirements/requirements-docs.txt \
    -r requirements/requirements-test.txt \
    -r requirements/requirements-lint.txt

COPY setup.py dev.py tox.ini recreate-fixtures.py ./
COPY --chown=django-ca:django-ca docs/ docs/
COPY --chown=django-ca:django-ca ca/ ca/
COPY --chown=django-ca:django-ca docker/localsettings.py ca/ca/localsettings.py

# Create some files/directories that we need later on
RUN touch .coverage
RUN mkdir -p /var/lib/django-ca/
RUN chown django-ca:django-ca .coverage /var/lib/django-ca/

# From here on, we run as normal user
USER django-ca:django-ca

# copy this late so that changes do not trigger a cache miss during build
RUN python dev.py code-quality
RUN python dev.py coverage --format=text
RUN make -C docs html-check
RUN python dev.py init-demo

###############
# Build stage #
###############
FROM build as prepare
COPY --from=build /install /install

COPY ca/ ca/
COPY docker/* ca/
COPY uwsgi/ uwsgi/
COPY nginx/ nginx/
RUN rm -rf requirements/ ca/django_ca/tests ca/ca/test_settings.py ca/ca/localsettings.py.example ca/.coverage

# Collect static files and remove source files
COPY dev.py .
ENV DJANGO_SETTINGS_MODULE=ca.settings
ENV DJANGO_CA_SETTINGS=ca/settings.yaml
ENV DJANGO_CA_SECRET_KEY=dummy
RUN SCRIPT_LOCATION=/install ./dev.py collectstatic

# Test that imports are working
RUN cp -a /install/* /usr/local/
RUN ./dev.py test-imports

# Remove files from working directory
RUN rm dev.py

###############
# final stage #
###############
FROM base
COPY --from=prepare /install /usr/local
COPY --from=prepare /usr/share/django-ca/static /usr/share/django-ca/static

RUN mkdir -p /usr/share/django-ca/static /usr/share/django-ca/media /var/lib/django-ca/ \
             /var/lib/django-ca/certs/ca/shared /var/lib/django-ca/certs/ocsp \
             /var/lib/django-ca/shared && \
    chown -R django-ca:django-ca /usr/share/django-ca/ /var/lib/django-ca/

COPY --from=prepare /usr/src/django-ca/ ./

USER django-ca:django-ca
EXPOSE 8000
VOLUME ["/var/lib/django-ca/", "/usr/share/django-ca/media/"]
WORKDIR /usr/src/django-ca/ca/
ENV DJANGO_CA_SETTINGS=settings.yaml
CMD ./uwsgi.sh
