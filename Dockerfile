ARG IMAGE=python:3.8-alpine3.10
####################
# Test build stage #
####################
FROM $IMAGE as test
WORKDIR /usr/src/django-ca

ENV SKIP_SELENIUM_TESTS=y

# NOTE: busybox installs /bin/sh
RUN apk --no-cache upgrade && \
    apk --no-cache add --update gcc linux-headers libc-dev libffi-dev openssl \
        openssl-dev make busybox
RUN pip install -U setuptools pip wheel


# Add user (some tests check if it's impossible to write a file)
RUN addgroup -g 9000 -S django-ca && \
    adduser -S -u 9000 -G django-ca django-ca

# Install additional requirements for testing:
COPY requirements.txt ./
COPY requirements/ requirements/
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

FROM $IMAGE as prepare

WORKDIR /usr/src/django-ca

# NOTE: busybox installs /bin/sh
RUN apk --no-cache upgrade && \
    apk --no-cache add --update gcc linux-headers libc-dev libffi-dev \
        openssl-dev pcre pcre-dev mailcap busybox mariadb-connector-c-dev \
        postgresql-dev

COPY requirements/ requirements/

RUN pip install -U pip setuptools wheel
RUN pip install --no-warn-script-location --no-cache-dir --prefix=/install \
    -r requirements/requirements-docker.txt \
    -r requirements/requirements-redis.txt \
    -r requirements/requirements-mysql.txt \
    -r requirements/requirements-postgres.txt

COPY ca/ ca/
COPY docker/ docker/
RUN mv docker/localsettings.py ca/ca/localsettings.py
RUN rm -rf requirements/ ca/django_ca/tests ca/ca/test_settings.py ca/ca/localsettings.py.example ca/.coverage

# Test that imports are working
RUN cp -a /install/* /usr/local/
ENV DJANGO_SETTINGS_MODULE=ca.settings
RUN cd ca && python -c "import django; \
django.setup(); \
from django.conf import settings; \
from django_ca import utils, models, views, extensions, subject"

######################
# Actual build stage #
######################
FROM $IMAGE
WORKDIR /usr/src/django-ca
RUN apk --no-cache upgrade && \
    apk --no-cache add --update pcre openssl-dev binutils busybox

RUN addgroup -g 9000 -S django-ca && \
    adduser -S -u 9000 -G django-ca django-ca && \
    mkdir -p /usr/share/django-ca/ /var/lib/django-ca/ && \
    chown django-ca:django-ca /usr/share/django-ca/ /var/lib/django-ca/

COPY --from=prepare /install /usr/local
COPY --from=prepare /usr/src/django-ca/ ./
COPY uwsgi/ uwsgi/

CMD docker/start.sh


USER django-ca:django-ca
EXPOSE 8000
VOLUME ["/var/lib/django-ca/", "/usr/share/django-ca/"]
