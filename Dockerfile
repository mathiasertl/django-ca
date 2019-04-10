ARG IMAGE=python:3.7-alpine3.9
####################
# Test build stage #
####################
FROM $IMAGE as test
WORKDIR /usr/src/django-ca
RUN apk --no-cache add --update gcc linux-headers libc-dev libffi-dev openssl-dev make

COPY requirements.txt ./
COPY requirements/ requirements/

# Add user (some tests check if it's impossible to write a file)
RUN addgroup -g 9000 -S django-ca && \
    adduser -S -u 9000 -G django-ca django-ca

RUN pip install -U setuptools pip
RUN pip install --no-cache-dir -r requirements/requirements-docker.txt

COPY setup.py dev.py tox.ini fabfile.py ./
COPY --chown=django-ca:django-ca docs/ docs/
COPY --chown=django-ca:django-ca ca/ ca/
COPY --chown=django-ca:django-ca docker/localsettings.py ca/ca/localsettings.py

# Make sure that requirements/requirements-docker.txt has installed all run-time dependencies
RUN python dev.py test-imports

# Install additional requirements for testing:
RUN pip install --no-cache-dir \
    -r requirements/requirements-docs.txt \
    -r requirements/requirements-test.txt \
    -r requirements/requirements-lint.txt

# From here on, we run as normal user
USER django-ca:django-ca

# copy this late so that changes do not trigger a cache miss during build
RUN python dev.py code-quality
RUN python dev.py coverage
RUN make -C docs html-check

FROM $IMAGE as prepare
WORKDIR /usr/src/django-ca

RUN apk --no-cache add --update gcc linux-headers libc-dev libffi-dev openssl-dev pcre pcre-dev mailcap

COPY requirements/ requirements/

RUN pip install --no-warn-script-location --no-cache-dir --prefix=/install -r requirements/requirements-docker.txt

COPY ca/ ca/
COPY docker/ docker/
RUN mv docker/localsettings.py ca/ca/localsettings.py
RUN rm -rf requirements/ ca/django_ca/tests ca/ca/test_settings.py ca/ca/localsettings.py.example ca/.coverage

######################
# Actual build stage #
######################
FROM $IMAGE
WORKDIR /usr/src/django-ca
RUN apk --no-cache add --update pcre openssl-dev binutils

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
