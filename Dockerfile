FROM python:3-alpine
WORKDIR /usr/src/django-ca

COPY requirements.txt docker/start.sh ./
COPY ca/ ca/
COPY uwsgi/ uwsgi/
COPY docker/localsettings.py ca/ca/
RUN apk --no-cache add --update gcc linux-headers libc-dev libffi-dev libressl-dev && \
    pip install --no-cache-dir -r requirements.txt uwsgi pyyaml
RUN addgroup -S django-ca && \
    adduser -S -G django-ca django-ca && \
    mkdir -p  /usr/share/django-ca/ /var/lib/django-ca/ && \
    chown django-ca:django-ca /usr/share/django-ca/ /var/lib/django-ca/

CMD ./start.sh

USER django-ca:django-ca
EXPOSE 8000
VOLUME ["/var/lib/django-ca/", "/usr/share/django-ca/"]
