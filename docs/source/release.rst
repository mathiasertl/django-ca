###############
Release process
###############

**************
Before release
**************

Check versions
==============

* Update ``requirements*.txt`` (use ``pip list -o``).
* Make sure that ``setup.py`` has proper requirements.
* Check ``.travis.yaml``.
* Check ``tox.ini``.
* Check ``NEWEST_PYTHON``, ``NEWEST_DJANGO`` and ``NEWEST_CRYPTOGRAPHY`` in ``test_settings.py``.
* Update ``VERSION`` and ``__version__`` in ``ca/django_ca/__init__.py``
  (see `PEP 440 <https://www.python.org/dev/peps/pep-0440/>`_).
* Update ``version`` parameter in ``setup.py``.

Other tasks
===========

* Check if any version of a dependency is no longer supported and we can depcreate support for it:

  * `Python <https://devguide.python.org/#status-of-python-branches>`_
  * `Django <https://www.djangoproject.com/download/>`_
  * `Alpine Linux <https://wiki.alpinelinux.org/wiki/Alpine_Linux:Releases>`_

* Make sure that ``setup.py`` has proper classifiers.
* Make sure that ``docs/source/changelog.rst`` is up to date.

Run testsuite
=============

* First, run ``./dev.py clean``.
* Check code quality (``./dev.py code-quality``).
* Check test coverage (``./dev.py coverage``).
* Make sure that ``./dev.py docker-test`` runs through.
* Make sure that ``tox`` runs through for all environments.

*********
Test demo
*********

Make sure that the demo works::

   rm -rf ca/db.sqlite3 ca/files/
   ./dev.py init-demo
   
   # test commands from the output:
   openssl verify -CAfile...

********************
Test admin interface
********************

* Check if the output of CAs and certs look okay: http://localhost:8000/admin
* Check if the profile selection when creating a certificate works.

************

Create a docker image:

.. code-block:: console

   export DOCKER_BUILDKIT=1
   docker build --progress=plain -t mathiasertl/django-ca .

... and follow instructions at :ref:`docker-use` to test the Docker image.

**************
docker-compose
**************

* Verify that docker-compose uses up-to-date version of 3rd-party containers.
* Follow instructions to test the docker-compose setup:

.. code-block:: console

   $ DJANGO_CA_CA_DEFAULT_HOSTNAME=localhost docker-compose up
   $ docker-compose exec backend ./manage.py createsuperuser
   $ docker-compose exec backend ./manage.py init_ca --pathlen=1 root /CN=example.com
   $ docker-compose exec backend ./manage.py init_ca \
   >     --path=ca/shared/ --parent=example.com child /CN=child.example.com

You should now be able to visit http://localhost/admin and log in. You are able to sign a certificate, but
*only* for the "child" CA.

In order to sign a certificate, we first need a private key and a CSR:

.. code-block:: console

   $ openssl genrsa -out cert.key 4096
   $ openssl req -new -key cert.key -out cert.csr -utf8 -batch \
   >     -subj '/CN=hostname/emailAddress=root@hostname'


Now, let's create a certificate for the root CA. Because it's only present for Celery, we need to create it
using the CLI:

.. code-block:: console

   $ docker-compose exec backend ./manage.py sign_cert --ca=example.com \
   >     --subject="/CN=signed-in-backend.example.com"

Check that the same fails in the frontend container (because the root CA is only available in the backend):

.. code-block:: console

   $ docker-compose exec frontend ./manage.py sign_cert --ca=example.com \
   >     --subject="/CN=signed-in-backend.example.com"

Finally, verify that CRL and OCSP validation works:

.. code-block:: console

   $ docker-compose exec backend ./manage.py dump_ca example.com > root.pem
   $ docker-compose exec backend ./manage.py dump_cert signed-in-backend.example.com > cert.pem
   $ openssl verify -CAfile root.pem -crl_download -crl_check cert.pem
   cert.pem: OK
   $ openssl x509 -in cert.pem -noout -text | grep OCSP 
         OCSP - URI:http://localhost/django_ca/ocsp/772198A6DAEF88A44C3F34780F0D657A60378EB1/cert/
   $ openssl ocsp -CAfile root.pem -issuer root.pem -cert cert.pem -resp_text \
   >     -url http://localhost/django_ca/ocsp/772198A6DAEF88A44C3F34780F0D657A60378EB1/cert/
   ...
   Response verify OK
   cert.pem: good


***************
Release process
***************

* Push the last commit and make sure that Travis and Read The Docs are updated.
* Tag the release: ``git tag -s $version -m "release $version"``
* Push the tag: ``git push origin --tags``
* Create a `release on GitHub <https://github.com/mathiasertl/django-ca/tags>`_.
* Create package for PyPi: ``python setup.py sdist bdist_wheel``.
* Upload package to PyPi: ``twine upload dist/*``
* Tag and upload the docker image  (note that we create a image revision by appending ``-1``)::

      docker tag mathiasertl/django-ca mathiasertl/django-ca:$version
      docker tag mathiasertl/django-ca mathiasertl/django-ca:$version-1
      docker push mathiasertl/django-ca:$version-1
      docker push mathiasertl/django-ca:$version
      docker push mathiasertl/django-ca

***************
After a release
***************

* Update ``VERSION`` and ``__version__`` in ``ca/django_ca/__init__.py`` to the next
  development release (see `PEP 440 <https://www.python.org/dev/peps/pep-0440/>`_).
* Update ``django_ca/deprecation.py``.
* Update version in ``setup.py``.
* Drop support for older software versions in ``.travis.yml``, ``tox.ini`` and ``dev.py docker-test``.
* Remove files in dist: ``rm -rf dist/*``
* Update ``docker-compose.yml`` to use the ``latest`` version of **django-ca**.
* Start new changelog entry in ``docs/source/changelog.rst``.
