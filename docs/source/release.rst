###############
Release process
###############

.. highlight:: console

**************
Before release
**************

Check versions
==============

* Update requirements in :file:`requirements*.txt` and :file:`setup.cfg` (use :command:`pip list -o`).
* Update ``[django-ca.release]`` in :file:`pyproject.toml`.
* Run :command:`devscripts/validate-state.py` and fix any errors.
* Update ``VERSION`` and ``__version__`` in :file:`ca/django_ca/__init__.py`
  (see `PEP 440 <https://www.python.org/dev/peps/pep-0440/>`_).
* Update the docker images in `dev.py docker-test`.

Other tasks
===========

* Check if any version of a dependency is no longer supported and we can deprecate support for it
  in the next release:

  * `Python <https://devguide.python.org/#status-of-python-branches>`_
  * `Django <https://www.djangoproject.com/download/>`_
  * `Alpine Linux <https://alpinelinux.org/releases/>`_

* Make sure that :file:`docs/source/changelog.rst` is up to date.

Run test suite
==============

Run all continuous integration tasks locally::

   $ ./dev.py clean
   $ ./dev.py code-quality
   $ ./dev.py coverage

Verify the documentation::

   $ doc8 docs/source
   $ make -C docs spelling
   $ make -C docs html-check

* Make sure that :command:`./dev.py docker-test` runs through.
* Make sure that :command:`tox` runs through for all environments.

*********
Test demo
*********

Make sure that the demo works and test the commands from the output::

   $ rm -rf ca/db.sqlite3 ca/files/
   $ ./dev.py init-demo
   $ openssl verify -CAfile...

***********
Test update
***********

Checkout the previous version and create a test data::

   $ git checkout $PREVIOUS_VERSION
   $ rm -rf ca/db.sqlite3 ca/files
   $ python ca/manage.py migrate
   $ devscripts/create-testdata.py

Then checkout the current master, run migrations and validate the test data::

   $ git checkout master
   $ python ca/manage.py migrate
   $ devscripts/validate-testdata.py

********************
Test admin interface
********************

* Check if the output of CAs and certs look okay: http://localhost:8000/admin
* Check if the profile selection when creating a certificate works.
* Check if pasting a CSR shows values from the CSR next to the "Subject" field.

******
Docker
******

Create a docker image::

   $ export DOCKER_BUILDKIT=1
   $ docker build --progress=plain -t mathiasertl/django-ca .

... and follow instructions at :ref:`docker-use` to test the Docker image.

**************
docker-compose
**************

* Verify that docker-compose uses up-to-date version of 3rd-party containers.
* Follow :doc:`quickstart_docker_compose` to set up a CA (but skip the TLS parts - no CA will issue a
  certificate for localhost). Don't forget to add an admin user and set up CAs.
* For this for your :file:`.env` file:

  .. code-block:: bash

     DJANGO_CA_CA_DEFAULT_HOSTNAME=localhost
     DJANGO_CA_CA_ENABLE_ACME=true
     POSTGRES_PASSWORD=mysecretpassword

After starting the setup, first verify that you're running the correct version::

   $ docker-compose exec backend manage shell -c "import django_ca; print(django_ca.__version__)"
   $ docker-compose exec frontend manage shell -c "import django_ca; print(django_ca.__version__)"

You should now be able to log in at http://localhost/admin. You are able to sign a certificate, but *only* for
the "child" CA.

In order to sign a certificate, we first need a private key and a CSR:

.. code-block:: console

   $ openssl genrsa -out cert.key 4096
   $ openssl req -new -key cert.key -out cert.csr -utf8 -batch \
   >     -subj '/CN=hostname/emailAddress=root@hostname'


Now, let's create a certificate for the root CA. Because it's only present for Celery, we need to create it
using the CLI:

.. code-block:: console

   $ docker-compose exec backend manage sign_cert --ca="Root CA" \
   >     --subject="/CN=signed-in-backend.example.com"
   Please paste the CSR:
   ...

Check that the same fails in the frontend container (because the root CA is only available in the backend):

.. code-block:: console

   $ docker-compose exec frontend manage sign_cert --ca="Root CA" \
   >     --subject="/CN=signed-in-backend.example.com"
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

***************
Release process
***************

* Push the last commit and make sure that GitHub actions, Travis and Read The Docs run through.
* Tag the release: :command:`git tag -s $version -m "release $version"`
* Push the tag: :command:`git push origin --tags`
* Create a `release on GitHub <https://github.com/mathiasertl/django-ca/tags>`_.
* Create package for PyPi::

      $ ./dev.py clean
      $ python setup.py sdist bdist_wheel
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

* Update ``VERSION`` and ``__version__`` in :file:`ca/django_ca/__init__.py` to the next
  development release (see `PEP 440 <https://www.python.org/dev/peps/pep-0440/>`_).
* Update :file:`django_ca/deprecation.py`.
* Drop support for older software versions in the ``[django-ca.release]`` section of in
  :file:`pyproject.toml`.
* Run :command:`devscripts/validate-state.py` and fix any errors.
* Update :file:`docker-compose.yml` to use the ``latest`` version of **django-ca**.
* Start new changelog entry in :file:`docs/source/changelog.rst`.
