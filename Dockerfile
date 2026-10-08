# syntax = docker/dockerfile:1.19.0
# check=error=true
# https://hub.docker.com/r/docker/dockerfile
# https://docs.docker.com/build/dockerfile/release-notes/
# Debian image used for building and testing. The Debian release must match the distroless image below.
ARG DEBIAN_CODENAME=trixie
ARG IMAGE=debian:${DEBIAN_CODENAME}-slim
# Image used for the final stage. "cc" contains glibc and libgcc, as required by uv-managed Python.
ARG DEBIAN_VERSION=13
ARG DISTROLESS_IMAGE=gcr.io/distroless/cc-debian${DEBIAN_VERSION}

# These arguments are used to more easily assure a consistent version
# with dev.py validate state
ARG UV=0.13

# Intermediate layer to be able to use a build argument in COPY --from below:
#   https://stackoverflow.com/a/63472135
FROM ghcr.io/astral-sh/uv:$UV AS uv

# Intermediate layer to be able to copy files from the distroless image.
FROM $DISTROLESS_IMAGE AS distroless

FROM $IMAGE AS base
WORKDIR /usr/src/django-ca

# Runtime libraries are only required for the test stage here, the final stage receives them from the
# runtime-libs stage below.
RUN --mount=target=/var/lib/apt/lists,type=cache,sharing=locked \
    --mount=target=/var/cache/apt,type=cache,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean &&  \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
         build-essential ca-certificates libpq-dev libmariadb-dev pkg-config softhsm2 openssl

# Add user (some tests check if it's impossible to write a file)
RUN groupadd --gid 9000 django-ca
RUN useradd --system --uid 9000 --gid 9000 \
    --shell /usr/sbin/nologin --no-create-home --home-dir /nonexistent \
    django-ca

# Install uv: https://docs.astral.sh/uv/guides/integration/docker/
COPY --from=uv /uv /uvx /bin/
ENV UV_LINK_MODE=copy
ENV UV_COMPILE_BYTECODE=1
ENV UV_LOCKED=1

# Use uv-managed Python, installed to a fixed location so that it can be copied to the final stage. The
# virtual environment references the interpreter by absolute path, so the path must be identical there.
ARG PYTHON=3.15
ENV UV_PYTHON_PREFERENCE=only-managed
ENV UV_PYTHON_INSTALL_DIR=/opt/python
ENV UV_PYTHON=$PYTHON
RUN --mount=type=cache,target=/root/.cache/uv,id=django-ca-uv-debian \
    uv python install --no-bin "$PYTHON"

# Install dependencies in separate step to improve caching and build performance. See also:
#   https://docs.astral.sh/uv/guides/integration/docker/#caching
# NOTE: intro.rst is needed as it's referenced package.readme and resolved by uv.
COPY docs/source/intro.rst docs/source/intro.rst
RUN --mount=type=cache,target=/root/.cache/uv,id=django-ca-uv-debian \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --all-extras --no-default-groups --group gunicorn --group DjangoLTS --no-install-project

COPY ca/django_ca/__init__.py ca/django_ca/
COPY pyproject.toml uv.lock ./

ARG DJANGO_CA_VERSION
ENV SETUPTOOLS_SCM_PRETEND_VERSION=$DJANGO_CA_VERSION
RUN --mount=type=cache,target=/root/.cache/uv,id=django-ca-uv-debian \
    uv sync --all-extras --no-default-groups --group gunicorn --group DjangoLTS

# Activate the virtual environment (even if it's not created yet).
ENV PATH="/usr/src/django-ca/.venv/bin:$PATH"
ENV VIRTUAL_ENV=/usr/src/django-ca/.venv

##############
# Test stage #
##############
FROM base AS test
ENV SKIP_SELENIUM_TESTS=y
ENV SQLITE_NAME=:memory:

# Install additional requirements for testing:
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --all-extras --no-default-groups --group dev

# Copy sources (doctests are run by test suite, CA files are used in tests)
COPY ca/ ca/
COPY docs/source/django_ca_sphinx/ docs/source/django_ca_sphinx/
COPY docs/source/_files/ca/ docs/source/_files/ca/
COPY docs/source/_files/cert/ docs/source/_files/cert/
COPY docs/source/_files/crl/ docs/source/_files/crl/
COPY docs/source/python/ docs/source/python/

# Run tests as normal user to assert that no write-access is required.
USER django-ca:django-ca

# Finally run tests
ARG FAIL_UNDER=100
ARG COVERAGE_ARGS="--cov-report=html:/tmp/coverage --cov-report term-missing --cov-fail-under=$FAIL_UNDER"
ENV COVERAGE_FILE=/tmp/.coverage
RUN pytest -vx $COVERAGE_ARGS --no-selenium
RUN touch /tmp/.coverage-sentinel

#################
# Prepare stage #
#################
FROM base AS prepare

COPY ca/ ca/
COPY conf/ ca/conf/
COPY gunicorn/ gunicorn/
COPY nginx/ nginx/
RUN mkdir ca/conf/local/

COPY devscripts/standalone/ devscripts/standalone/

RUN rm -rf ca/django_ca/tests ca/ca/test_settings.py ca/ca/localsettings.py.example

# Test that imports are working
RUN python devscripts/standalone/clean.py
RUN DJANGO_CA_SECRET_KEY=dummy devscripts/standalone/test-imports.py --all-extras

# Finally, clean up to minimize the image
RUN python devscripts/standalone/clean.py
RUN rm -rf pyproject.toml ca/django_ca/migrations/pyproject.toml devscripts/pyproject.toml docs/
RUN python devscripts/standalone/check-clean-docker.py --ignore-devscripts
RUN rm -rf devscripts/

# With BuildKit, the test stage is never executed unless we depend on it
COPY --from=test /tmp/.coverage-sentinel /tmp

#########################################
# Runtime libraries for the final stage #
#########################################
# The distroless image has no package manager. Debian packages are instead downloaded and extracted to
# /rootfs/ here, which is then copied to the final stage. Packages already present in the distroless image
# are skipped. Package metadata is written to /var/lib/dpkg/status.d/ (the same layout used by distroless
# itself), so that vulnerability scanners still detect the packages. Note that maintainer scripts (postinst,
# ...) are *not* executed.
FROM $IMAGE AS runtime-libs
COPY --from=distroless /var/lib/dpkg/status.d/ /tmp/distroless-status.d/

WORKDIR /tmp/debs
RUN --mount=target=/var/lib/apt/lists,type=cache,sharing=locked \
    --mount=target=/var/cache/apt,type=cache,sharing=locked \
    set -eu; \
    rm -f /etc/apt/apt.conf.d/docker-clean; \
    apt-get update; \
    # Packages already present in the distroless image.
    grep -h '^Package:' /tmp/distroless-status.d/* | awk '{print $2}' | sort -u > /tmp/present; \
    # Dependency closure of the packages we need (virtual packages like "<foo>" are filtered out).
    apt-cache depends --recurse --no-recommends --no-suggests --no-conflicts \
        --no-breaks --no-replaces --no-enhances \
        libpq5 libmariadb3 \
        | grep '^[a-z0-9]' | sort -u > /tmp/wanted; \
    comm -23 /tmp/wanted /tmp/present > /tmp/needed; \
    echo "Adding packages:"; cat /tmp/needed; \
    chown _apt /tmp/debs; \
    apt-get download $(cat /tmp/needed); \
    mkdir -p /rootfs/var/lib/dpkg/status.d; \
    for deb in *.deb; do \
        pkg=$(dpkg-deb -f "$deb" Package); \
        dpkg-deb -x "$deb" /rootfs; \
        dpkg-deb -f "$deb" | sed '1a Status: install ok installed' > "/rootfs/var/lib/dpkg/status.d/$pkg"; \
    done; \
    # Files in non-merged /usr locations would conflict with the symlinks in the distroless image.
    for dir in bin sbin lib lib64; do \
        if [ -e "/rootfs/$dir" ]; then echo "/$dir found in extracted packages." >&2; exit 1; fi; \
    done

##################
# Assemble stage #
##################
# Assemble the filesystem of the final image in a stage that still has a shell.
FROM base AS assemble

RUN mkdir -p /usr/share/django-ca/static /usr/share/django-ca/media /var/lib/django-ca/ \
             /var/lib/django-ca/certs/ca/shared /var/lib/django-ca/certs/ocsp \
             /var/lib/django-ca/shared /var/lib/django-ca/nginx/templates/ \
             /run/django-ca && \
    chown -R django-ca:django-ca /usr/share/django-ca/ /var/lib/django-ca/ /run/django-ca/ && \
    chmod 0700 /run/django-ca/

COPY --from=prepare /usr/src/django-ca/ ./
RUN ln -s /usr/src/django-ca/ca/manage.py /usr/local/bin/manage

COPY scripts/ /usr/src/django-ca/scripts/
# Wrapper scripts are installed without the .py suffix (e.g. "django-ca-gunicorn").
# NOTE: Legacy shell scripts (celery.sh, ...) are not installed, as the final image has no shell.
COPY scripts/django-ca-*.py scripts/django_ca_startup.py /usr/src/django-ca/scripts/
RUN for script in /usr/src/django-ca/scripts/django-ca-*.py; do \
        ln -s "${script}" "/usr/local/bin/$(basename "${script}" .py)"; \
    done

# The final image has no /usr/bin/env, so use the interpreter from the virtual environment directly.
RUN sed -i '1s|^#!/usr/bin/env python3$|#!/usr/src/django-ca/.venv/bin/python|' \
        /usr/src/django-ca/ca/manage.py /usr/src/django-ca/scripts/django-ca-*.py

# Add the django-ca user to the user/group database of the distroless image.
COPY --from=distroless /etc/passwd /etc/group /tmp/distroless/
RUN mkdir -p /rootfs/etc && \
    cp /tmp/distroless/passwd /tmp/distroless/group /rootfs/etc/ && \
    echo "django-ca:x:9000:9000:django-ca:/var/lib/django-ca:/sbin/nologin" >> /rootfs/etc/passwd && \
    echo "django-ca:x:9000:" >> /rootfs/etc/group && \
    chmod 0644 /rootfs/etc/passwd /rootfs/etc/group

# Collect everything into /rootfs/, preserving ownership, permissions and symlinks.
RUN cp -a --parents /usr/share/django-ca/ /var/lib/django-ca/ /run/django-ca/ /usr/src/django-ca/ \
        /usr/local/bin/ /rootfs/

###############
# final stage #
###############
FROM distroless

COPY --from=runtime-libs /rootfs/ /
COPY --from=base /opt/python/ /opt/python/
COPY --from=assemble /rootfs/ /

ENV PATH="/usr/src/django-ca/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ENV VIRTUAL_ENV=/usr/src/django-ca/.venv

# NOTE: Kubernetes’ runAsNonRoot can only verify numeric IDs, not names.
USER 9000:9000
EXPOSE 8000
VOLUME ["/var/lib/django-ca/", "/usr/share/django-ca/media/"]
WORKDIR /usr/src/django-ca/ca/


# Smoke test: verify that compiled extensions and the libraries they link to load in the final image.
# RTLD_NOW resolves all symbols on load, so that missing libraries or symbol version mismatches fail here and
# not on first use.
RUN ["python", "-B", "-c", "import os, sys; sys.setdlopenflags(os.RTLD_NOW); import ssl, sqlite3, ctypes, psycopg, psycopg_c, MySQLdb, pkcs11; from cryptography.hazmat.bindings._rust import openssl; assert psycopg.pq.__impl__ == 'c', psycopg.pq.__impl__"]

ENV DJANGO_CA_SETTINGS=conf/:conf/local

CMD [ "django-ca-gunicorn" ]
