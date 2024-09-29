# syntax = docker/dockerfile:1.6.0
# https://hub.docker.com/r/docker/dockerfile
# https://docs.docker.com/build/dockerfile/release-notes/
ARG IMAGE=python:3.12-alpine3.20

FROM $IMAGE as base
WORKDIR /usr/src/django-ca

RUN --mount=type=cache,target=/etc/apk/cache apk upgrade
RUN --mount=type=cache,target=/etc/apk/cache apk add --update \
        pcre openssl tzdata binutils busybox softhsm \
        libpq postgresql-client mariadb-connector-c mariadb-client

# Add user (some tests check if it's impossible to write a file)
RUN addgroup -g 9000 -S django-ca && \
    adduser -S -u 9000 -G django-ca django-ca

FROM base as build
RUN --mount=type=cache,target=/etc/apk/cache apk add \
        build-base linux-headers libffi libffi-dev openssl-dev \
        pcre-dev mailcap mariadb-connector-c-dev postgresql-dev cargo

RUN --mount=type=cache,target=/root/.cache/pip/http pip install -U setuptools pip wheel

COPY requirements/ requirements/
COPY ca/django_ca/__init__.py ca/django_ca/
COPY pyproject.toml requirements-pinned.txt ./
COPY --chown=django-ca:django-ca docs/source/intro.rst docs/source/intro.rst
RUN --mount=type=cache,target=/root/.cache/pip/http \
    pip install --no-warn-script-location --ignore-installed --prefix=/install \
        -r requirements/requirements-docker.txt \
        -r requirements-pinned.txt \
        -e .[celery,hsm,mysql,postgres,redis,yaml]

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
COPY pyproject.toml ./
COPY --chown=django-ca:django-ca ca/ ca/

# Create some files/directories that we need later on
RUN mkdir -p /var/lib/django-ca/
RUN chown django-ca:django-ca /var/lib/django-ca/ /usr/src/django-ca/ca

# From here on, we run as normal user
USER django-ca:django-ca

# doctests are run by test suite, CA files are also loaded
COPY docs/source/ docs/source/

# Finally run tests
ARG FAIL_UNDER=100
ENV COVERAGE_FILE=/tmp/.coverage
# Alpine currently does not support all key types or EC curves
ENV PKCS11_EXCLUDE_KEY_TYPES='Ed448'
ENV PKCS11_EXCLUDE_ELLIPTIC_CURVES='sect163r2,sect571r1,sect409r1,sect283r1,sect233k1,sect283k1,sect409k1,sect233r1,sect571k1,sect163k1'
RUN pytest -v  --cov-report term-missing --cov-fail-under=$FAIL_UNDER -p no:cacheprovider --no-selenium

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

RUN rm -rf requirements-pinned.txt requirements/ ca/django_ca/tests ca/ca/test_settings.py ca/ca/localsettings.py.example

# Test that imports are working
RUN cp -a /install/* /usr/local/
RUN python devscripts/standalone/clean.py
RUN DJANGO_CA_SECRET_KEY=dummy devscripts/standalone/test-imports.py --all-extras

# Finally, clean up to minimize the image
RUN python devscripts/standalone/clean.py
RUN rm -rf pyproject.toml docs/
RUN python devscripts/standalone/check-clean-docker.py --ignore-devscripts
RUN rm -rf devscripts/

# Seems like with BuildKit, the test stage is never executed unless we somehow depend on it
COPY --from=test /usr/src/django-ca/docs/build/coverage/ /tmp

###############
# final stage #
###############
FROM base
COPY --from=build /install /usr/local

RUN mkdir -p /usr/share/django-ca/static /usr/share/django-ca/media /var/lib/django-ca/ \
             /var/lib/django-ca/certs/ca/shared /var/lib/django-ca/certs/ocsp \
             /var/lib/django-ca/shared /var/lib/django-ca/nginx/templates/ && \
    chown -R django-ca:django-ca /usr/share/django-ca/ /var/lib/django-ca/

COPY --from=prepare /usr/src/django-ca/ ./
RUN ln -s /usr/src/django-ca/ca/manage.py /usr/local/bin/manage

USER django-ca:django-ca
EXPOSE 8000
VOLUME ["/var/lib/django-ca/", "/usr/share/django-ca/media/"]
WORKDIR /usr/src/django-ca/ca/

ENV DJANGO_CA_SETTINGS=conf/
ENV DJANGO_CA_SECRET_KEY_FILE=/var/lib/django-ca/certs/ca/shared/secret_key

CMD ./uwsgi.sh
