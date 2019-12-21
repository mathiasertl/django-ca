ARG IMAGE=python:3.8-alpine3.10

FROM $IMAGE as base
WORKDIR /usr/src/django-ca
RUN apk --no-cache upgrade && \
    apk --no-cache add --update pcre openssl binutils busybox libpq postgresql-client

# Add user (some tests check if it's impossible to write a file)
RUN addgroup -g 9000 -S django-ca && \
    adduser -S -u 9000 -G django-ca django-ca

FROM base as build
RUN apk --no-cache add --update build-base linux-headers libffi-dev openssl-dev \
        pcre-dev mailcap mariadb-connector-c-dev postgresql-dev
RUN pip install -U setuptools pip wheel

COPY requirements.txt ./
COPY requirements/ requirements/
RUN pip install --no-warn-script-location --no-cache-dir --prefix=/install \
    -r requirements/requirements-docker.txt \
    -r requirements/requirements-redis.txt \
    -r requirements/requirements-mysql.txt \
    -r requirements/requirements-postgres.txt

##############
# Test stage #
##############
FROM build as test
COPY --from=build /install /usr/local
ENV SKIP_SELENIUM_TESTS=y

# Install additional requirements for testing:
RUN pip install --no-cache-dir \
    -r requirements/requirements-docker.txt \
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
COPY --from=build /install /usr/local

COPY ca/ ca/
COPY docker/ docker/
RUN mv docker/localsettings.py ca/ca/localsettings.py
RUN rm -rf requirements/ ca/django_ca/tests ca/ca/test_settings.py ca/ca/localsettings.py.example ca/.coverage

# Test that imports are working
ENV DJANGO_SETTINGS_MODULE=ca.settings
RUN cd ca && python -c "import django; \
django.setup(); \
from django.conf import settings; \
from django_ca import utils, models, views, extensions, subject"

###############
# final stage #
###############
FROM base
COPY --from=build /install /usr/local

RUN mkdir -p /usr/share/django-ca/ /var/lib/django-ca/ && \
    chown django-ca:django-ca /usr/share/django-ca/ /var/lib/django-ca/

COPY --from=prepare /usr/src/django-ca/ ./
COPY uwsgi/ uwsgi/

CMD docker/start.sh


USER django-ca:django-ca
EXPOSE 8000
VOLUME ["/var/lib/django-ca/", "/usr/share/django-ca/"]
