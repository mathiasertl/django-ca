###############
Release process
###############

.. highlight:: console

***********
Preparation
***********

Run these steps when you begin to create a new release:

* Double-check that the changelog is up to date.
* Update requirements in :file:`requirements*.txt` and :file:`setup.cfg` (use :command:`pip list -o`).
* Check versions of major software dependencies and:

  * Update ``[django-ca.release]`` in :file:`pyproject.toml` with current minor versions.
  * Add a deprecation notice for versions no longer supported upstream.

* Verify that :file:`docker-compose.yml` uses up-to-date version of 3rd-party containers.
* Run :command:`devscripts/validate-state.py` and fix any errors.

******************
Test current state
******************

* Make sure that :command:`tox` runs through for all environments.
* Make sure that :command:`./dev.py docker-test` runs through.

Test demo
=========

Make sure that the demo works and test the commands from the output (``manage.py runserver`` should obviously
be run in a separate shell)::

   $ ./dev.py clean
   $ ./dev.py init-demo
   $ python ca/manage.py runserver
   $ openssl verify -CAfile...

Test update
===========

Checkout the previous version and create a test data::

   $ git checkout $PREVIOUS_VERSION
   $ rm -rf ca/db.sqlite3 ca/files
   $ python ca/manage.py migrate
   $ devscripts/create-testdata.py

Then checkout the current master, run migrations and validate the test data::

   $ git checkout master
   $ python ca/manage.py migrate
   $ python ca/manage.py makemigrations --check
   $ devscripts/validate-testdata.py

Test admin interface
====================

* Check if the output of CAs and certs look okay: http://localhost:8000/admin
* Check if the profile selection when creating a certificate works.
* Check if pasting a CSR shows values from the CSR next to the "Subject" field.

******
Docker
******

Create the docker image::

   $ docker system prune -af
   $ export DOCKER_BUILDKIT=1
   $ docker build --progress=plain -t mathiasertl/django-ca .

Testing
=======

Do some basic sanity checking of the Docker image::

   $ docker run -e DJANGO_CA_SECRET_KEY=dummy --rm \
   >     mathiasertl/django-ca manage shell -c \
   >     "import django_ca; print(django_ca.__version__)"
   ...
   $ docker run --rm \
   >     -v `pwd`/setup.cfg:/usr/src/django-ca/setup.cfg \
   >     -v `pwd`/devscripts/:/usr/src/django-ca/devscripts \
   >     -w /usr/src/django-ca/ \
   >     mathiasertl/django-ca devscripts/test-imports.py --all-extras

Finally follow :doc:`docker` and make sure that everything works:

* Use ``localhost`` instead of ``ca.example.com`` as a hostname.
* You cannot test ACMEv2 this way, as challenge validation would not work.

**************
docker-compose
**************

* Follow :doc:`quickstart_docker_compose` to set up a CA (but skip the TLS parts - no CA will issue a
  certificate for localhost). Don't forget to add an admin user and set up CAs.
* Use this for your :file:`.env` file:

  .. code-block:: bash

     DJANGO_CA_CA_DEFAULT_HOSTNAME=localhost
     DJANGO_CA_CA_ENABLE_ACME=true
     POSTGRES_PASSWORD=mysecretpassword

After starting the setup, first verify that you're running the correct version::

   $ docker-compose exec backend manage shell -c "import django_ca; print(django_ca.__version__)"
   $ docker-compose exec frontend manage shell -c "import django_ca; print(django_ca.__version__)"

You should now be able to log in at http://localhost/admin. You are able to sign a certificate, but *only* for
the "child" CA.

Now, let's create a certificate for the root CA. Because it's only present for Celery, we need to create it
using the CLI:

.. code-block:: console

   $ cat ca/django_ca/tests/fixtures/root-cert.csr | \
   >     docker-compose exec -T backend manage sign_cert --ca="Root CA" \
   >        --subject="/CN=signed-in-backend.example.com"
   Please paste the CSR:
   ...

Check that the same fails in the frontend container (because the root CA is only available in the backend):

.. code-block:: console

   $ cat ca/django_ca/tests/fixtures/root-cert.csr | \
   >     docker-compose exec frontend manage sign_cert --ca="Root CA" \
   >        --subject="/CN=signed-in-backend.example.com"
   ...
   manage sign_cert: error: argument --ca: Root: ca/...key: Private key does not exist.

Finally, verify that CRL and OCSP validation works:

.. code-block:: console

   $ docker-compose exec backend manage dump_ca "Root CA" > root.pem
   $ docker-compose exec backend manage dump_cert signed-in-backend.example.com > cert.pem
   $ openssl verify -CAfile root.pem -crl_download -crl_check cert.pem
   cert.pem: OK
   $ openssl x509 -in cert.pem -noout -text | grep OCSP
         OCSP - URI:http://localhost/django_ca/ocsp/...
   $ openssl ocsp -CAfile root.pem -issuer root.pem -cert cert.pem -resp_text \
   >     -url http://localhost/django_ca/ocsp/...
   ...
   Response verify OK
   cert.pem: good

Finally, clean up the test setup:

.. code-block:: console

   $ docker-compose down -v

Test update
===========

* Checkout the previous version on git:

  .. code-block:: console

     $ git checkout $PREVIOUS_VERSION

* Add a basic :file:`.env` file:

  .. code-block:: bash

     DJANGO_CA_CA_DEFAULT_HOSTNAME=localhost
     DJANGO_CA_CA_ENABLE_ACME=true
     POSTGRES_PASSWORD=mysecretpassword

* If testing ``django_ca<=1.17.3``, update image versions :file:`docker-compose.yml`.
* Start the old version with::

     $ DJANGO_CA_VERSION=$PREVIOUS_VERSION docker-compose up -d

* Create test data::

     $ docker cp devscripts/create-testdata.py \
     >   django-ca_backend_1:/usr/src/django-ca/ca/
     $ docker cp devscripts/create-testdata.py \
     >   django-ca_frontend_1:/usr/src/django-ca/ca/
     $ docker-compose exec backend ./create-testdata.py --env backend
     $ docker-compose exec frontend ./create-testdata.py --env frontend

* Log into the admin interface and create some certificates.
* Update to the newest version::

     $ git checkout master
     $ DJANGO_CA_VERSION=latest docker-compose up -d

* Finally, validate that data was correctly migrated::

     $ docker cp devscripts/validate-testdata.py \
     >   django-ca_backend_1:/usr/src/django-ca/ca/
     $ docker cp devscripts/validate-testdata.py \
     >   django-ca_frontend_1:/usr/src/django-ca/ca/
     $ docker-compose exec backend ./validate-testdata.py --env backend
     $ docker-compose exec frontend ./validate-testdata.py --env frontend

Test ACMEv2
===========

First, make sure you're starting from a clean slate::

   $ docker-compose down -v

Start the stack again, but this time add a second docker-compose override-file (we use the ``COMPOSE_FILE``
environment variable here)::

   $ export COMPOSE_FILE="docker-compose.yml:ca/django_ca/tests/fixtures/docker-compose.certbot.yaml"
   $ docker-compose build
   $ docker-compose up -d
   $ docker-compose exec backend manage createsuperuser
   $ docker-compose exec backend manage init_ca \
   >  --pathlen=1 Root "/CN=Root CA"
   $ docker-compose exec backend manage init_ca \
   >  --acme-enable \
   >  --path=ca/shared/ --parent="Root CA" Intermediate "/CN=Intermediate CA"

You should be able to view the admin interface at http://localhost/admin. But the additional docker-compose
override file adds a certbot container, that you can use to get certificates (note that certbot is already
configured to use the local registry)::

   $ docker-compose exec certbot /bin/bash
   root@certbot:~# certbot register
   IMPORTANT NOTES:
    - Your account credentials have been saved in your Certbot
   ...
   root@certbot:~# django-ca-test-validation.sh http http-01.example.com
   + certbot certonly ...
   ...
   http-01 challenge for http-01.example.com
   ...

   IMPORTANT NOTES:
    - Congratulations! Your certificate and chain have been saved at:
   ...
   root@certbot:~# django-ca-test-validation.sh dns dns-01.example.com
   + certbot certonly ...
   ...
   dns-01 challenge for dns-01.example.com
   ...
   IMPORTANT NOTES:
    - Congratulations! Your certificate and chain have been saved at:
   ...


***************
Release process
***************

* Push the last commit and make sure that GitHub actions and Read The Docs run through.
* Tag the release: :command:`git tag -s $version -m "release $version"`
* Push the tag: :command:`git push origin --tags`
* Create a `release on GitHub <https://github.com/mathiasertl/django-ca/tags>`_.
* Create package for PyPi::

      $ ./dev.py clean
      $ python -m build
      $ twine check --strict dist/*

* Upload package to PyPi: :command:`twine upload dist/*`
* Tag and upload the docker image  (note that we create a image revision by appending ``-1``)::

      $ docker tag mathiasertl/django-ca mathiasertl/django-ca:$version
      $ docker tag mathiasertl/django-ca mathiasertl/django-ca:$version-1
      $ docker push mathiasertl/django-ca:$version-1
      $ docker push mathiasertl/django-ca:$version
      $ docker push mathiasertl/django-ca

***************
After a release
***************

* Update :file:`django_ca/deprecation.py`.
* Drop support for older software versions in the ``[django-ca.release]`` section of in
  :file:`pyproject.toml`.
* Run :command:`devscripts/validate-state.py` and fix any errors.
* Update :file:`docker-compose.yml` to use the ``latest`` version of **django-ca**.
* Start new changelog entry in :file:`docs/source/changelog.rst`.
