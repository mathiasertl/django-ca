###############
Release process
###############

.. highlight:: console

***********
Preparation
***********

Run these steps when you begin to create a new release:

* Double-check that the changelog is up to date.
* Update requirements in :file:`requirements*.txt` and :file:`pyproject.toml` (use :command:`pip list -o`).
* Check versions of major software dependencies and:

  * Update ``[django-ca.release]`` in :file:`pyproject.toml` with current minor versions.
  * Add a deprecation notice for versions no longer supported upstream.

* Update table in ``docs/source/quickstart/as_app.rst``
* Run :command:`./dev.py validate state` and fix any errors.
* Update version in ``ca/django_ca/__init__.py``.

Pin requirements
================

Create a file with pinned requirements, so that users can reliably reproduce a setup::

   $ ./dev.py pin-requirements

docker-compose
==============

* Verify that :file:`docker-compose.yml` uses up-to-date version of 3rd-party containers.
* Set the default django-ca version in :file:`docker-compose.yml` to the new version.
* Update table in ``docs/source/quickstart/docker_compose.rst``.

******************
Test current state
******************

* Make sure that :command:`tox` runs through for all environments.
* Make sure that :command:`./dev.py docker-test` runs through.
* Push the last commit and make sure that GitHub actions and Read The Docs run through.

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
   $ devscripts/standalone/create-testdata.py

Then checkout the current main branch, run migrations and validate the test data::

   $ git checkout main
   $ python ca/manage.py migrate
   $ python ca/manage.py makemigrations --check
   $ devscripts/standalone/validate-testdata.py

Finally, also make sure that ``devscripts/standalone/create-testdata.py`` also works for the current version::

   $ rm -rf ca/db.sqlite3 ca/files
   $ python ca/manage.py migrate
   $ devscripts/standalone/create-testdata.py
   $ devscripts/standalone/validate-testdata.py

Test admin interface
====================

* Check if the output of CAs and certs look okay: http://localhost:8000/admin
* Check if the profile selection when creating a certificate works.
* Check if pasting a CSR shows values from the CSR next to the "Subject" field.

****************
Create a release
****************

Create a release with::

   $ ./dev.py release $version

The release script will:

* Validate the current state in your repository.
* Create a new signed git tag.
* Build and validate the Python Wheel.
* Build and test the Docker image.
* Test the various tutorials.
* Upload Python Wheel and Docker image.

************************
Create release on GitHub
************************

Create a `release on GitHub <https://github.com/mathiasertl/django-ca/tags>`_.

***************
After a release
***************

* Update version in ``ca/django_ca/__init__.py``.
* Update :file:`ca/django_ca/deprecation.py` and remove code marked by such warnings.
* Search for deprecation comments that could be removed::

      $ grep -A 3 -r 'deprecated:' docs/source/ ca/

* Drop support for older software versions in the ``[django-ca.release]`` section of :file:`pyproject.toml`.
* Run :command:`./dev.py validate state` and fix any errors.
* Look for pragmas that indicate that code can be removed due to versions no longer being supported::

      $ grep -r '# pragma:' ca/ docs/source/ devscripts/ *.py

* Update :file:`docker-compose.yml` to use the ``latest`` version of **django-ca**.
* Start new changelog entry in :file:`docs/source/changelog.rst`.
