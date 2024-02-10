#################
How-To Contribute
#################

To contribute to **django-ca** simply do a fork on `on github <https://github.com/mathiasertl/django-ca>`_ and
submit a pull request when you're happy.

When doing a pull request, please make sure to explain what your improvement does or what bug is fixed by it
and how to reproduce this locally.

**********************
Initialize environment
**********************

To create a virtual environment for development, you need a compatible Python version as well as a few
development headers. Under Debian/Ubuntu, you can install everything with:

.. code-block:: console

   $ apt install python3 python3-venv python3-dev gcc libpq-dev

Virtual environment
===================

To create and activate a virtual environment:

.. code-block:: console

   $ python3 -m venv venv/
   $ venv/bin/pip install -U pip setuptools wheel
   $ venv/bin/pip install -r requirements.txt -r requirements-dev.txt
   $ source venv/bin/activate
   (venv) $

Local configuration
===================

To run the Djangos integrated development webserver, create some minimal local configuration as YAML file:

.. code-block:: YAML

    DEBUG: true
    SECRET_KEY: dummy
    ALLOWED_HOSTS:
      - localhost

    # django-ca configuration
    CA_DEFAULT_HOSTNAME: "localhost:8000"
    CA_ENABLE_ACME: true
    CA_ENABLE_REST_API: true

    # Set to true if you want to use Celery
    CA_USE_CELERY: false

Initialize demo
===============

You can *optionally* initialize the demo, which will generate several certificate authorities and
certificates:

.. code-block:: console

   $ ./dev.py init-demo

Run local webserver
===================

If you need to run the local webserver (to test the API, OCSP or CRL URLs or the admin interface):

.. code-block:: console

   $ python ca/manage.py runserver

************************
Testing and Code quality
************************

This project is very rigorous about quality standards for both code and documentation. Please see
:doc:`/dev/testing` for help on running (and writing) tests and :doc:`/dev/standards` for help with quality
checks.

**********************
Generate documentation
**********************

To generate the documentation in ``docs/build/html/``, simply run:

.. code-block:: console

   $ doc8 docs/source/
   $ make -C docs clean spelling html