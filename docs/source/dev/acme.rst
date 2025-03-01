################
ACME development
################

.. highlight:: console

*********
Standards
*********

* `RFC 8555: ACMEv2 <https://tools.ietf.org/html/rfc8555>`_
* `RFC 7515: JSON Web Signature (JWS) <https://tools.ietf.org/html/rfc7515>`_
* `RFC 7517: JSON Web Key (JWK) <https://tools.ietf.org/html/rfc7515>`_
* `RFC 7638: JSON Web Key (JWK) Thumbprint <https://tools.ietf.org/html/rfc7638>`_

*******
Testing
*******

Test using certbot
==================

The project includes a specialized Docker Compose override file so that you can start django-ca using
``docker compose`` and then use a container to use certbot.

If you want to test the current development state, you must first locally build the image::

   $ DOCKER_BUILDKIT=1 docker build -t mathiasertl/django-ca:latest .

Then start the setup with the override file and you'll get a complete setup and a `certbot` container that can
be used to retrieve certificates. The DNS of setup so that the CA can be reached at ``ca.example.com``::

   $ export COMPOSE_FILE=compose.yaml:ca/django_ca/tests/fixtures/docker-compose.certbot.yaml
   $ docker compose up -d
   ...
   $ docker compose exec backend manage createsuperuser
   ...
   $ docker compose exec backend manage init_ca \
   >     --path-length=1 Root CN=Root
   $ docker compose exec backend manage init_ca --path-length=0 --path=ca/shared/ \
   >     --parent=Root --acme-enable Intermediate CN=Intermediate

After that, you can login to the web interface at http://localhost/admin/ to view progress.

You can now start a shell in the ``certbot`` container and request a certificate. Note that certbot is
preconfigured to use the django-ca registry in the container next to it::

   $ docker compose exec certbot /bin/bash
   root@certbot:~# certbot register
   root@certbot:~# django-ca-test-validation.sh http http-01.example.com
   root@certbot:~# django-ca-test-validation.sh dns dns-01.example.com

Use certbot directly
====================

You can use certbot with a server started via ``manage.py runserver`` to test issuing certificates for
localhost::

   # certbot register --agree-tos -m user@localhost \
   >    --config-dir=.certbot/config/ --work-dir=.certbot/work/ --logs-dir=.certbot/logs \
   >    --server http://localhost:8000/django_ca/acme/directory/

   # certbot certonly --standalone \
   >    --config-dir=.certbot/config/ --work-dir=.certbot/work/ --logs-dir=.certbot/logs \
   >    --server http://localhost:8000/django_ca/acme/directory/ \
   >    -d localhost

You can revoke a certificate::

   # certbot revoke \
   >     --config-dir=.certbot/config/ --work-dir=.certbot/work/ --logs-dir=.certbot/logs \
   >     --server http://localhost:8000/django_ca/acme/directory/ \
   >     --cert-name localhost

Use a different configuration/work directory if you "lost your account key"::

   # certbot revoke \
   >     --config-dir=.certbot1/config/ --work-dir=.certbot1/work/ --logs-dir=.certbot1/logs \
   >     --server http://localhost:8000/django_ca/acme/directory/ \
   >     --key-path .certbot/config/archive/localhost/privkey1.pem \
   >     --cert-path .certbot/config/archive/localhost/fullchain1.pem \
   >     --reason keycompromise

***************
Tips and tricks
***************

Query LE::

   $ curl -v https://acme-v02.api.letsencrypt.org/directory

base64url encoding
==================

ACMEv2 uses the `Base 64 Encoding with URL and Filename Safe Alphabet
<https://datatracker.ietf.org/doc/html/rfc4648#section-5>`_ encoding for binary data. This is similar but not
identical to standard  base64 encoding.

The ACME library does that with `josepy <https://pypi.org/project/josepy/>`_ (which is **not** the
similar/forked? `python-jose <https://pypi.org/project/python-jose/>`_):

.. code-block:: python3

   >>> import josepy as jose
   >>> jose.b64encode(b'test')
   b'dGVzdA'
   >>> jose.b64decode(b'dGVzdA')
   b'test'
