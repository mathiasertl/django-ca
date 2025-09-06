# syntax = docker/dockerfile:1.10.0
# https://hub.docker.com/r/docker/dockerfile
# https://docs.docker.com/build/dockerfile/release-notes/
ARG IMAGE=python:3.13-slim-trixie

FROM $IMAGE AS base
WORKDIR /usr/src/django-ca

RUN --mount=target=/var/lib/apt/lists,type=cache,sharing=locked \
    --mount=target=/var/cache/apt,type=cache,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean &&  \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
         lsb-release netcat-openbsd postgresql-client mariadb-client

# Add user (some tests check if it's impossible to write a file)
RUN adduser --system --uid=9000 --group --disabled-login django-ca

# Activate the virtual environment (even if it's not created yet).
ENV PATH="/usr/src/django-ca/.venv/bin:$PATH"
ENV VIRTUAL_ENV=/usr/src/django-ca/.venv

FROM base AS build

# Install uv: https://docs.astral.sh/uv/guides/integration/docker/
COPY --from=ghcr.io/astral-sh/uv:0.6.6 /uv /uvx /bin/

COPY ca/django_ca/__init__.py ca/django_ca/
COPY pyproject.toml uv.lock ./
COPY docs/source/intro.rst docs/source/intro.rst

RUN --mount=target=/var/lib/apt/lists,type=cache,sharing=locked \
    --mount=target=/var/cache/apt,type=cache,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean &&  \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
         build-essential libpq-dev libmariadb-dev pkg-config

ENV UV_PYTHON_PREFERENCE=only-system
ENV UV_LINK_MODE=copy
ARG DJANGO_CA_VERSION
ENV SETUPTOOLS_SCM_PRETEND_VERSION_FOR_DJANGO_CA=$DJANGO_CA_VERSION
RUN --mount=type=cache,target=/root/.cache/uv,id=django-ca-uv-debian \
    uv sync --frozen --all-extras --no-default-groups --group gunicorn --compile-bytecode

##############
# Test stage #
##############
FROM build AS test
ENV SKIP_SELENIUM_TESTS=y
ENV SQLITE_NAME=:memory:

# Install additional requirements for testing:
RUN --mount=target=/var/lib/apt/lists,type=cache,sharing=locked \
    --mount=target=/var/cache/apt,type=cache,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean &&  \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        softhsm2
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --all-extras --group dev

# Copy sources (doctests are run by test suite, CA files are used in tests)
COPY ca/ ca/
COPY docs/source/ docs/source/

# Run tests as normal user to assert that no write-access is required.
USER django-ca:django-ca

# Finally run tests
ARG FAIL_UNDER=100
ENV COVERAGE_FILE=/tmp/.coverage
RUN pytest -v --cov-report=html:/tmp/coverage --cov-report term-missing --cov-fail-under=$FAIL_UNDER --no-selenium -x

###############
# Build stage #
###############
FROM build AS prepare

COPY ca/ ca/
COPY conf/ ca/conf/
COPY gunicorn/ gunicorn/
COPY nginx/ nginx/

COPY devscripts/standalone/ devscripts/standalone/

RUN rm -rf ca/django_ca/tests ca/ca/test_settings.py ca/ca/localsettings.py.example

# Test that imports are working
RUN python devscripts/standalone/clean.py
RUN DJANGO_CA_SECRET_KEY=dummy python devscripts/standalone/test-imports.py --all-extras

# Finally, clean up to minimize the image
RUN python devscripts/standalone/clean.py
RUN rm -rf pyproject.toml ca/django_ca/migrations/pyproject.toml devscripts/pyproject.toml docs/
RUN python devscripts/standalone/check-clean-docker.py --ignore-devscripts
RUN rm -rf devscripts/

# With BuildKit, the test stage is never executed unless we depend on it
COPY --from=test /tmp/.coverage /tmp

###############
# final stage #
###############
FROM base

RUN mkdir -p /usr/share/django-ca/static /usr/share/django-ca/media /var/lib/django-ca/ \
             /var/lib/django-ca/certs/ca/shared /var/lib/django-ca/certs/ocsp \
             /var/lib/django-ca/shared /var/lib/django-ca/nginx/templates/ && \
    chown -R django-ca:django-ca /usr/share/django-ca/ /var/lib/django-ca/

COPY --from=prepare /usr/src/django-ca/ ./
RUN ln -s /usr/src/django-ca/ca/manage.py /usr/local/bin/manage

COPY scripts/ /usr/src/django-ca/scripts/
RUN ln -s /usr/src/django-ca/scripts/*.sh /usr/local/bin/

USER django-ca:django-ca
EXPOSE 8000
VOLUME ["/var/lib/django-ca/", "/usr/share/django-ca/media/"]
WORKDIR /usr/src/django-ca/ca/

ENV DJANGO_CA_SETTINGS=conf/
ENV DJANGO_CA_SECRET_KEY_FILE=/var/lib/django-ca/certs/ca/shared/secret_key

CMD [ "gunicorn.sh" ]
