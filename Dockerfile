FROM python:3
WORKDIR /usr/src/django-ca

RUN mkdir -p /var/lib/django-ca/ /usr/share/django-ca/
COPY requirements.txt docker/start.sh ./
COPY ca/ ca/
COPY uwsgi/ uwsgi/
COPY docker/localsettings.py ca/ca/
RUN pip install --no-cache-dir -r requirements.txt uwsgi pyyaml
RUN groupadd -r django-ca && useradd --no-log-init -r -g django-ca django-ca
RUN chown django-ca:django-ca /var/lib/django-ca/

# Collect static files
RUN python ca/manage.py collectstatic --noinput

CMD ./start.sh

USER django-ca:django-ca
EXPOSE 8000
VOLUME ["/var/lib/django-ca/"]
