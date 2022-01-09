######################
Quickstart from source
######################

This guide provides instructions for running your own certificate authority by installing django-ca from
source. This method requires a lot of manual configuration and a lot of expert knowledge, but is a good choice
if you use an exotic system or other options do not work for you for some reason. If you're looking for a
faster and easier option, you might consider using :doc:`docker-compose <quickstart_docker_compose>`.

.. NOTE::

   All commands below assume that you have a shell with superuser privileges.

This tutorial will give you a CA with

* A root and intermediate CA.
* A browsable admin interface, protected by TLS (using Let's Encrypt certificates).
* Certificate revocation using CRLs and OCSP.
* (Optional) ACMEv2 support (= get certificates using certbot).

.. jinja:: requirements-from-source
   :file: include/guide-requirements.rst.jinja
   :header_update_levels:

Required software
=================

.. jinja:: full-requirements-from-source
   :file: include/guide-full-requirements.rst.jinja
   :header_update_levels:

On Debian/Ubuntu, simply do:

.. code-block:: console

   user@host:~# apt update
   user@host:~# apt install python3 python3-venv python3-dev \
   >  gcc libpq-dev postgresql postgresql-client \
   >  redis-server nginx uwsgi uwsgi-plugin-python3

************
Installation
************

Get the source
==============

You can clone django-ca from git or download an archive `from GitHub
<https://github.com/mathiasertl/django-ca/releases>`_. In the example below, we extract the source to
``/opt/django-ca/src/`` and create an unversioned symlink so that you can roll back to old versions during an
update:

.. jinja::
   :file: include/guide-get-source.rst.jinja

Create a virtualenv
===================

In our setup, we create a `virtualenv <https://docs.python.org/3/tutorial/venv.html>`_ to install the Python
environment. Several tools building on virtualenv exist (e.g. `pyenv <https://github.com/pyenv/pyenv>`_ or
`virtualenvwrapper <https://virtualenvwrapper.readthedocs.io/en/latest/>`_) that you might want to try out.

.. WARNING::

   Do not run pip as root and outside of a virtualenv. This will update system dependencies and potentially
   breaks your system!

.. code-block:: console

   user@host:~# python3 -m venv /opt/django-ca/venv/
   user@host:~# source /opt/django-ca/venv/bin/activate
   (venv) user@host:~# pip install -U pip setuptools
   (venv) user@host:~# pip install -e /opt/django-ca/src/django-ca[postgres,acme,celery,redis]

Add user
========

Add a system user to run uWSGI (the application server) and Celery (the task worker):

.. code-block:: console

   user@host:~# adduser --system --group --disabled-login --home=/opt/django-ca/home/ django-ca

PostgreSQL and nginx
====================

Create a PostgreSQL database and make sure to use a randomly generated password and keep it for later
configuration:

.. code-block:: console

   user@host:~# sudo -u postgres psql
   postgres=# CREATE DATABASE django_ca;
   CREATE DATABASE
   postgres=# CREATE USER django_ca WITH ENCRYPTED PASSWORD 'random-password';
   CREATE ROLE
   postgres=# GRANT ALL PRIVILEGES ON DATABASE django_ca TO django_ca;
   GRANT

TODO: nginx config

Add SystemD services
====================

SystemD services are included with **django-ca**. You need to add two services, one for the uWSGI application
server and one for the Celery task worker. To enable them, just create symlinks in ``/etc/systemd/system/``:

.. code-block:: console

   user@host:~# ln -s /opt/django-ca/src/django-ca/systemd/django-ca.service /etc/systemd/system/
   user@host:~# ln -s /opt/django-ca/src/django-ca/systemd/django-ca-celery.service /etc/systemd/system/
   user@host:~# systemctl daemon-reload

Note that the services will not yet start due to :ref:`missing configuration <from-source-configuration>`. If
you use a root directory different from ``/opt/django-ca/``, add a SystemD override for the
``WorkingDirectory=`` directive and the ``DJANGO_CA_BASE_DIR`` environment variable.

.. _from-source-configuration:

*************
Configuration
*************

*****
Start
*****

Create admin user and set up CAs
================================

Where to go from here
=====================

******
Update
******
