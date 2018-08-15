####################
# Test build stage #
####################
FROM python:3-alpine as test
WORKDIR /usr/src/django-ca
COPY requirements.txt requirements-dev.txt setup.py ./
RUN apk --no-cache add --update gcc linux-headers libc-dev libffi-dev libressl-dev

# Additional utilities required for testing:
RUN apk --no-cache add --update make
RUN pip install --no-cache-dir -r requirements.txt -r requirements-dev.txt

# copy this late so that changes do not trigger a cache miss during build
COPY ca/ ca/
RUN python setup.py test

# cleanup some files so they are not included later
RUN rm -r ca/django_ca/tests/
RUN find ca/
RUN find ca/ | grep pyc$ | xargs rm
RUN find ca/ -type d | grep __pycache__ | xargs rmdir

######################
# Actual build stage #
######################
FROM python:3-alpine
WORKDIR /usr/src/django-ca

COPY requirements.txt docker/start.sh ./
RUN apk --no-cache add --update gcc linux-headers libc-dev libffi-dev libressl-dev && \
    pip install --no-cache-dir -r requirements.txt uwsgi pyyaml
RUN addgroup -S django-ca && \
    adduser -S -G django-ca django-ca && \
    mkdir -p /usr/share/django-ca/ /var/lib/django-ca/ && \
    chown django-ca:django-ca /usr/share/django-ca/ /var/lib/django-ca/
COPY --from=test /usr/src/django-ca/ca/ ca/
COPY uwsgi/ uwsgi/
COPY docker/localsettings.py ca/ca/

CMD ./start.sh

USER django-ca:django-ca
EXPOSE 8000
VOLUME ["/var/lib/django-ca/", "/usr/share/django-ca/"]
