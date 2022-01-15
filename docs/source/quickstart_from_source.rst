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
   >     gcc libpq-dev postgresql postgresql-client \
   >     redis-server nginx uwsgi uwsgi-plugin-python3

************
Installation
************

With this guide, you will install **django-ca** to ``/opt/django-ca/``, with your local configuration residing
in ``/etc/django-ca/``. You also need to create a system user to run the uWSGI application server and Celery
task worker: 

.. code-block:: console

   user@host:~# mkdir -p /opt/django-ca/src/ /etc/django-ca/
   user@host:~# adduser --system --group --disabled-login --home=/opt/django-ca/home/ django-ca
   user@host:~# adduser django-ca www-data

Get the source
==============

You can clone django-ca from git or download an archive `from GitHub
<https://github.com/mathiasertl/django-ca/releases>`_. In the example below, we extract the source to
``/opt/django-ca/src/`` and create a symlink without a version so that you can roll back to old versions
during an update:

.. jinja::
   :file: include/guide-get-source.rst.jinja

Create a virtualenv
===================

In our setup, we create a `virtualenv <https://docs.python.org/3/tutorial/venv.html>`_ to install the Python
environment. Several tools building on virtualenv exist (e.g. `pyenv <https://github.com/pyenv/pyenv>`_ or
`virtualenvwrapper <https://virtualenvwrapper.readthedocs.io/en/latest/>`_) that you might want to try out.

.. WARNING::

   Always run pip in a virtualenv or it will update system dependencies and break your system!

.. code-block:: console

   user@host:~# python3 -m venv /opt/django-ca/venv/
   user@host:~# source /opt/django-ca/venv/bin/activate
   (venv) user@host:~# pip install -U pip setuptools
   (venv) user@host:~# pip install -U PyYAML
   (venv) user@host:~# pip install -U -e /opt/django-ca/src/django-ca[postgres,acme,celery,redis]

PostgreSQL database
===================

Create a PostgreSQL database and make sure to use a randomly generated password and keep it for later
configuration:

.. code-block:: console

   user@host:~# openssl rand -base64 32
   ...
   user@host:~# sudo -u postgres psql
   postgres=# CREATE DATABASE django_ca;
   CREATE DATABASE
   postgres=# CREATE USER django_ca WITH ENCRYPTED PASSWORD 'random-password';
   CREATE ROLE
   postgres=# GRANT ALL PRIVILEGES ON DATABASE django_ca TO django_ca;
   GRANT

.. _from-source-add-systemd-services:

Add SystemD services
====================

SystemD services are included with **django-ca**. You need to add two services, one for the uWSGI application
server and one for the Celery task worker:

.. code-block:: console

   user@host:~# ln -s /opt/django-ca/src/django-ca/systemd/systemd.conf /etc/django-ca/
   user@host:~# ln -s /opt/django-ca/src/django-ca/systemd/*.service /etc/systemd/system/
   user@host:~# systemctl daemon-reload
   user@host:~# systemctl enable django-ca django-ca-celery

Note that the services will not yet start due to :ref:`missing configuration <from-source-configuration>`.

If you use an installation directory other then ``/opt/django-ca``, set ``INSTALL_BASE`` in
:file:`/etc/systemd/systemd-local.conf` (see :ref:`systemd-configuration`) *and* add a SystemD override for
``WorkingDirectory=``.

.. _from-source-configuration:

*************
Configuration
*************

**django-ca** will load configuration from all ``*.yaml`` files in ``/etc/django-ca/`` in alphabetical order.
These files can contain any `Django setting <https://docs.djangoproject.com/en/4.0/ref/settings/>`_, `Celery
setting <https://docs.celeryproject.org/en/stable/userguide/configuration.html>`_ or :doc:`django-ca setting
<settings>`.

If you (mostly) followed the above examples, you can symlink :file:`conf/source/00-settings.yaml` to
``/etc/django-ca`` and just override a few settings in :file:`/etc/django-ca/10-localsettings.yaml`. To create
the symlink:

.. code-block:: console

   user@host:~# ln -s /opt/django-ca/src/django-ca/conf/source/00-settings.yaml /etc/django-ca/

And then simply create a minimal :file:`/etc/django-ca/10-localsettings.yaml` - but you can override any other
setting here as well:

.. literalinclude:: /_files/from-source/localsettings.yaml
   :language: yaml
   :caption: /etc/django-ca/10-localsettings.yaml
   :name: /etc/django-ca/10-localsettings.yaml

.. _systemd-configuration:

SystemD configuration
=====================

When you :ref:`added SystemD services <from-source-add-systemd-services>` you also created a symlink for
:file:`/etc/django-ca/systemd.conf`. If any of the settings there do not suit you, you can override them in
:file:`/etc/django-ca/systemd-local.conf`.

.. _from-source-add-manage-py-shortcut:

Add manage.py shortcut
======================

As optional convenience, you can create a symlink to a small wrapper script that allows you to easily run
``manage.py`` commands. In the examples below the guide assumes you created this symlink at
:file:`/usr/local/bin/django-ca`, but of course name the symlink anything you like:

.. code-block:: console

   user@host:~# ln -s /opt/django-ca/src/django-ca/conf/source/manage /usr/local/bin/django-ca
   user@host:~# django-ca check
   System check identified no issues (0 silenced).

Setup
=====

Finally, you can populate the database and setup the static files directory:

.. code-block:: console

   user@host:~# django-ca migrate
   user@host:~# USER=root django-ca collectstatic

The ``collectstatic`` command needs to run as root.

*****
Start
*****

You can now finally start the uWSGI application server and the Celery worker (omit ``django-ca`` service if
you do not intend to run a web server):

.. code-block:: console

   user@host:~# systemctl start django-ca django-ca-celery

Create admin user and set up CAs
================================

Because we :ref:`created a shortcut above <from-source-add-manage-py-shortcut>` above, we can use
``django-ca`` to use **django-ca** from the command line.

.. jinja:: manage-from-source
   :file: include/create-user.rst.jinja

Setup NGINX
===========

Finally, it's time to setup NGINX. A web server is required for the admin interface, certificate revocation
status via OCSP or CRLs and of course also ACMEv2 (the protocol used by Let's Encrypt/certbot integration).

.. WARNING::

   You might be tempted to setup NGINX using certificates retrieved via a local CAs ACMEv2 interface. This is
   theoretically possible, but creates a chicken-and-egg situation where a misconfiguration will make it
   impossible to retrieve a certificate.

In this setup, we'll create certificates using the CA we created above. If you want to use Let's Encrypt
certificates instead, you can have a look at our :doc:`quickstart_docker_compose`.

Where to go from here
=====================

******
Update
******

*********
Uninstall
*********

To completely uninstall **django-ca**, stop related services and remove files that where created:

.. code-block:: console

   user@host:~# systemctl stop django-ca django-ca-celery
   user@host:~# systemctl disable django-ca django-ca-celery
   user@host:~# rm -f /etc/nginx/sites-*/django-ca.conf
   user@host:~# rm -f /usr/local/bin/django-ca
   user@host:~# rm -rf /etc/django-ca/ /opt/django-ca/

Restart NGINX so that it no longer knows about the configurations:

.. code-block:: console

   user@host:~# systemctl restart nginx

Remove the system user:

.. code-block:: console

   user@host:~# deluser django-ca

Drop the PostgreSQL database:

.. code-block:: console

   user@host:~# sudo -u postgres psql
   postgres=# DROP DATABASE django_ca;
   DROP DATABASE
   postgres=# DROP USER django_ca;
   DROP ROLE
