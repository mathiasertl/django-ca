ARG IMAGE=python:3.7-alpine3.8
####################
# Test build stage #
####################
FROM $IMAGE as test
WORKDIR /usr/src/django-ca
RUN apk --no-cache add --update gcc linux-headers libc-dev libffi-dev libressl-dev make

COPY requirements.txt requirements-dev.txt setup.py tox.ini fabfile.py ./
COPY requirements/ requirements/

# Additional utilities required for testing:
RUN pip install --no-cache-dir -r requirements.txt \
    -r requirements/requirements-docs.txt \
    -r requirements/requirements-test.txt

COPY ca/ ca/
COPY docs/ docs/

# Add user (some tests check if it's impossible to write a file)
RUN addgroup -g 9000 -S django-ca && \
    adduser -S -u 9000 -G django-ca django-ca
USER django-ca:django-ca

# copy this late so that changes do not trigger a cache miss during build
RUN python setup.py code_quality
RUN python setup.py test

FROM 3.7-alpine3.8 as prepare

RUN apk --no-cache add --update gcc linux-headers libc-dev libffi-dev libressl-dev pcre pcre-dev mailcap

COPY requirements/ requirements/
RUN pip install --no-cache-dir --install-option="--prefix=/install" -r requirements/requirements-docker.txt


######################
# Actual build stage #
######################
FROM python:3.7-alpine3.8
WORKDIR /usr/src/django-ca

COPY requirements.txt ./
COPY requirements/ requirements/
#RUN apk --no-cache add --update gcc linux-headers libc-dev libffi-dev libressl-dev pcre pcre-dev mailcap
COPY --from=prepare /install /usr/local
RUN addgroup -g 9000 -S django-ca && \
    adduser -S -u 9000 -G django-ca django-ca && \
    mkdir -p /usr/share/django-ca/ /var/lib/django-ca/ && \
    chown django-ca:django-ca /usr/share/django-ca/ /var/lib/django-ca/
COPY --from=test /usr/src/django-ca/ca/ ca/
COPY uwsgi/ uwsgi/
COPY docker/ docker/

CMD docker/start.sh

USER django-ca:django-ca
EXPOSE 8000
VOLUME ["/var/lib/django-ca/", "/usr/share/django-ca/"]
