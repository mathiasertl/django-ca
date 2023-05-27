# syntax = docker/dockerfile:1.4.3
# https://hub.docker.com/r/docker/dockerfile
ARG IMAGE=python:3.11-alpine3.17

FROM $IMAGE as base
WORKDIR /usr/src/django-ca

RUN --mount=type=cache,target=/etc/apk/cache apk upgrade
RUN --mount=type=cache,target=/etc/apk/cache apk add --update \
        pcre openssl tzdata binutils busybox libpq postgresql-client mariadb-connector-c mariadb-client

# Add user (some tests check if it's impossible to write a file)
RUN addgroup -g 9000 -S django-ca && \
    adduser -S -u 9000 -G django-ca django-ca

FROM base as build
RUN --mount=type=cache,target=/etc/apk/cache apk add \
        build-base linux-headers libffi libffi-dev openssl-dev \
        pcre-dev mailcap mariadb-connector-c-dev postgresql-dev cargo

COPY requirements/ requirements/
RUN --mount=type=cache,target=/root/.cache/pip/http pip install -U setuptools pip wheel

COPY ca/django_ca/__init__.py ca/django_ca/
COPY setup.cfg setup.py pyproject.toml ./
COPY --chown=django-ca:django-ca docs/source/intro.rst docs/source/intro.rst
# NOTE: pinning cryptography to <38, version 38 implements CSR version validation
RUN --mount=type=cache,target=/root/.cache/pip/http \
    pip install --no-warn-script-location --ignore-installed --prefix=/install \
        -r requirements/requirements-docker.txt \
        -e .[celery,acme,redis,mysql,psycopg3] \
        "cryptography<38"


# Finally, copy sources
COPY ca/ ca/

##############
# Test stage #
##############
FROM build as test
COPY --from=build /install /usr/local
ENV SKIP_SELENIUM_TESTS=y
ENV SQLITE_NAME=:memory:

# Install additional requirements for testing:
RUN --mount=type=cache,target=/root/.cache/pip/http pip install \
    -r requirements/requirements-test.txt

# copy this late so that changes do not trigger a cache miss during build
COPY tox.ini pyproject.toml ./
COPY setup.py dev.py ./
COPY --chown=django-ca:django-ca ca/ ca/

# Create some files/directories that we need later on
RUN touch .coverage
RUN mkdir -p /var/lib/django-ca/
RUN chown django-ca:django-ca .coverage /var/lib/django-ca/ /usr/src/django-ca/ca

# From here on, we run as normal user
USER django-ca:django-ca

# doctests are run by test suite, CA files are also loaded
COPY docs/source/ docs/source/

# Run linters and unit tests
COPY devscripts/ devscripts/
ARG FAIL_UNDER=100
RUN python dev.py coverage --format=text --fail-under=$FAIL_UNDER

###############
# Build stage #
###############
FROM build as prepare
COPY --from=build /install /install

COPY ca/ ca/
COPY scripts/* ca/
COPY conf/ ca/conf/
COPY uwsgi/ uwsgi/
COPY nginx/ nginx/

COPY devscripts/ devscripts/

RUN rm -rf requirements/ ca/django_ca/tests ca/ca/test_settings.py ca/ca/localsettings.py.example 

# Test that imports are working
RUN cp -a /install/* /usr/local/
RUN python devscripts/standalone/clean.py
COPY setup.cfg ./
RUN DJANGO_CA_SECRET_KEY=dummy devscripts/standalone/test-imports.py

# Finally, clean up to minimize the image
RUN python devscripts/standalone/clean.py
RUN rm -rf setup.py setup.cfg pyproject.toml docs/
RUN python devscripts/standalone/check-clean-docker.py --ignore-devscripts
RUN rm -rf devscripts/

# Seems like with BuildKit, the test stage is never executed unless we somehow depend on it
COPY --from=test /usr/src/django-ca/.coverage /tmp

###############
# final stage #
###############
FROM base
COPY --from=build /install /usr/local

RUN mkdir -p /usr/share/django-ca/static /usr/share/django-ca/media /var/lib/django-ca/ \
             /var/lib/django-ca/certs/ca/shared /var/lib/django-ca/certs/ocsp \
             /var/lib/django-ca/shared && \
    chown -R django-ca:django-ca /usr/share/django-ca/ /var/lib/django-ca/

COPY --from=prepare /usr/src/django-ca/ ./
RUN ln -s /usr/src/django-ca/ca/manage.py /usr/local/bin/manage

USER django-ca:django-ca
EXPOSE 8000
VOLUME ["/var/lib/django-ca/", "/usr/share/django-ca/media/"]
WORKDIR /usr/src/django-ca/ca/
ENV DJANGO_CA_SETTINGS=conf/
CMD ./uwsgi.sh
