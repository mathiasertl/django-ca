FROM python:3-alpine
WORKDIR /usr/src/django-ca

COPY requirements.txt docker/start.sh ./
RUN apk --no-cache add --update gcc libc-dev linux-headers libffi-dev libressl-dev && \
    pip install --no-cache-dir -r requirements.txt uwsgi pyyaml
RUN mkdir -p /var/lib/django-ca/ /usr/share/django-ca/
COPY ca/ ca/
COPY uwsgi/ uwsgi/
COPY docker/localsettings.py ca/ca/
RUN addgroup -S django-ca && \
    adduser -S -h /usr/share/django-ca/ -G django-ca -H django-ca && \
    chown django-ca:django-ca /var/lib/django-ca/

# Collect static files
RUN python ca/manage.py collectstatic --noinput

CMD ./start.sh

USER django-ca:django-ca
EXPOSE 8000
VOLUME ["/var/lib/django-ca/"]
