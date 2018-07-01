FROM python:3
WORKDIR /usr/src/django-ca

RUN mkdir -p /var/lib/django-ca/ /usr/share/django-ca/
COPY ca/ ca/
COPY docker/localsettings.py ca/ca/
COPY docker/standalone.ini /etc/django-ca/
RUN pip install --no-cache-dir -r requirements.txt uwsgi
RUN groupadd -r django-ca && useradd --no-log-init -r -g django-ca django-ca
RUN chown django-ca:django-ca /var/lib/django-ca/

# Collect static files
RUN python ca/manage.py collectstatic --noinput

CMD python ca/manage.py migrate --noinput && uwsgi --ini /etc/django-ca/standalone.ini

USER django-ca:django-ca
EXPOSE 8000
VOLUME ["/etc/django-ca/", "/var/lib/django-ca/"]
