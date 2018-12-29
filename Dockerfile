ARG IMAGE=python:3.7-alpine3.8
####################
# Test build stage #
####################
FROM $IMAGE as test
WORKDIR /usr/src/django-ca
RUN apk --no-cache add --update gcc linux-headers libc-dev libffi-dev libressl-dev make

COPY requirements.txt ./
COPY requirements/ requirements/

# Additional utilities required for testing:
RUN pip install --no-cache-dir -r requirements.txt \
    -r requirements/requirements-docs.txt \
    -r requirements/requirements-test.txt

# Add user (some tests check if it's impossible to write a file)
RUN addgroup -g 9000 -S django-ca && \
    adduser -S -u 9000 -G django-ca django-ca
USER django-ca:django-ca

COPY setup.py tox.ini fabfile.py ./
COPY ca/ ca/
COPY --chown=django-ca:django-ca docs/ docs/

# copy this late so that changes do not trigger a cache miss during build
RUN python setup.py code_quality
RUN python setup.py test
RUN make -C docs html-check

FROM python:3.7-alpine3.8 as prepare
WORKDIR /usr/src/django-ca

RUN apk --no-cache add --update gcc linux-headers libc-dev libffi-dev libressl-dev pcre pcre-dev mailcap

COPY requirements/ requirements/

RUN pip install --no-cache-dir --prefix=/install -r requirements/requirements-docker.txt

COPY ca/ ca/
COPY docker/ docker/
RUN cp docker/localsettings.py ca/ca/localsettings.py
RUN rm -rf ca/django_ca/tests ca/ca/test_settings.py ca/ca/localsettings.py.example

######################
# Actual build stage #
######################
FROM python:3.7-alpine3.8
WORKDIR /usr/src/django-ca
RUN apk --no-cache add --update pcre libressl-dev binutils

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
