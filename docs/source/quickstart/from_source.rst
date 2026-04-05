######################
Quickstart from source
######################

.. structured-tutorial:: source/tutorial.yaml

This guide provides instructions for running your own certificate authority by installing django-ca from
source. This method requires a lot of manual configuration and a lot of expert knowledge, but is a good choice
if you use an exotic system or other options do not work for you for some reason. If you're looking for a
faster and easier option, you might consider using :doc:`Docker Compose </quickstart/docker_compose>`.

.. NOTE::

    This tutorial uses `structured-tutorials <https://structured-tutorials.readthedocs.io/en/latest/>`_.

    This means that the documentation you see here is rendered from a configuration file and can also be run
    locally to verify correctness and completeness.

.. NOTE::

   All commands below assume that you have a shell with superuser privileges.

This tutorial will give you a CA with

* A root and intermediate CA.
* A browsable admin interface, protected by TLS (using certificates signed by your CA).
* Certificate revocation using CRLs and OCSP.
* (Optional) ACMEv2 support (= get certificates using certbot).

************
Requirements
************

.. include:: /include/guide-requirements.rst


Required software
=================

To run **django-ca**, you need Python, a database and a web server (like NGINX or Apache).

Whenever this tutorial installs software, it assumes a Debian/Ubuntu based system. If you use a different
distribution, refer to their manuals for instructions. We assume that the APT cache is up to date and you have
some basics installed:

.. structured-tutorial-part:: apt-update

Install database
----------------
**django-ca** will not run without a `supported database
<https://docs.djangoproject.com/en/dev/ref/databases/>`_. This tutorial will show you how to use PostgreSQL
or MariaDB. To install either:

.. structured-tutorial-part:: install-db

Install cache
-------------

Using a distributed cache is highly recommended. This tutorial will show you how to use `Memcached
<https://memcached.org/>`_ or `Redis <https://redis.io/>`_. To install either:

.. structured-tutorial-part:: install-cache

Install broker for Celery
-------------------------

Using `Celery <https://docs.celeryq.dev/>`_ is optional but also highly recommended for performance and
security reasons. If you use Celery, the web server does not need to use the private key (or the HSM
storing the private key). If you want to split the setup across multiple hosts, only those running Celery
need to be able to sign data (certificates, CRLs, ...).

For Celery, you'll need a broker. Redis can double as a broker, but you can use a variety
of `other systems <https://docs.celeryq.dev/en/main/getting-started/backends-and-brokers/index.html>`_. This
tutorial will show you how to use Redis or `RabbitMQ <https://www.rabbitmq.com/>`_.

Redis was already installed above, as it can double as a cache. If you want to use RabbitMQ instead:

.. structured-tutorial-part:: install-broker

Install :command:`uv`
---------------------

Additionally, this guide uses :command:`uv` to set up a Python Virtual Environment. Please refer to the `installation
instructions <https://docs.astral.sh/uv/getting-started/installation/>`_ for how to install it. On most Linux
systems you can simply run:

.. structured-tutorial-part:: install-uv

Later in the tutorial, we will let :command:`uv` manage python versions. This allows you to use the newest
Python version regardless of what your distribution (version) offers. :command:`uv` will install Python
versions in ``/root/`` by default, which then can not be accessed by Gunicorn and Celery (which run with a
lower-privileged user):

.. structured-tutorial-part:: install-uv-python

Environment
===========

To make the guide less error-prone, we export the domain name for your certificate authority to
``$HOSTNAME``. In all commands below assume that you have set the environment variable like this:

.. structured-tutorial-part:: set-hostname


************
Installation
************

With this guide, you will install **django-ca** to ``/opt/django-ca/``, with your local configuration residing
in ``/etc/django-ca/``.

Start by creating a system user and some essential directories:

.. structured-tutorial-part:: prepare-host

.. _from-source-create-database:

Create database
===============

Create a database and make sure to use a randomly generated password. You will need to again when
configuring django-ca:

.. structured-tutorial-part:: setup-database

Setup broker
============

If you use Redis as a broker, you can use it out of the box. For RabbitMQ, a little configuration is
necessary:

.. structured-tutorial-part:: setup-broker

.. _from-source-add-systemd-services:

Get the source
==============

You can clone django-ca from git or download an archive `from GitHub
<https://github.com/mathiasertl/django-ca/releases>`_. In the example below, we extract the source to
``/opt/django-ca/src/`` and create a symlink without a version so that you can roll back to old versions
during an update:

.. structured-tutorial-part:: install-source

Create a virtualenv
===================

We use `uv <https://docs.astral.sh/uv/>`_ to create and manage the Python environment. By default, ``uv`` will
manage both a local Python installation and `virtualenv <https://docs.python.org/3/tutorial/venv.html>`_ for
you, but you can instruct it to use the system Python installation (try ``uv sync --help``).

.. structured-tutorial-part:: create-virtualenv

Depending on your needs you might also want to disable other extras as well. This is a list of all currently
available extras:

.. include:: /include/pip-extras.rst

You can of course use a regular `virtualenv` and ``pip`` to manage your environment as well. For example:

.. code-block:: console

   root@host:~# cd /opt/django-ca/src/django-ca/
   root@host:/opt/django-ca/src/django-ca/# python3 -m venv .venv/
   root@host:/opt/django-ca/src/django-ca/# .venv/bin/pip install -U \
   >     pip setuptools wheel
   root@host:/opt/django-ca/src/django-ca/# .venv/bin/pip install -U \
   >     -e /opt/django-ca/src/django-ca[api,hsm,postgres,celery,redis,yaml]

Add SystemD services
====================

SystemD services are included with **django-ca**. You need to add three services, one for the Gunicorn
application server (``django-ca``), one for the Celery task worker (``django-ca-celery``) and one for the
Celery task scheduler (``django-ca-celerybeat``):

.. structured-tutorial-part:: add-systemd-services

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
</settings>`.

If you (mostly) followed the above examples, you can symlink :file:`conf/source/00-settings.yaml` to
``/etc/django-ca`` and just override a few settings in :file:`/etc/django-ca/10-localsettings.yaml`. To create
the symlink:

.. structured-tutorial-part:: add-basic-settings

And then simply create a minimal :file:`/etc/django-ca/10-localsettings.yaml` - but you can override any other
setting here as well:

.. structured-tutorial-part:: add-required-settings

Please see :doc:`/settings` for a list of available settings.

Configure the database
======================

Configure database access in a dedicated configuration file. Use the ``PASSWORD`` you used when you
:ref:`created a database <from-source-create-database>`:

.. structured-tutorial-part:: add-db-settings

Configure the cache
===================

Configure the cache in a dedicated configuration file:

.. structured-tutorial-part:: add-cache-settings

Configure broker
================

Configure the Broker used by Celery in a dedicated configuration file:

.. structured-tutorial-part:: add-broker-settings

Configure Gunicorn
==================

Gunicorn requires a dedicated configuration file. Minimal default settings are included in django-ca:

.. structured-tutorial-part:: add-gunicorn-config

If you need different `Gunicorn settings <https://gunicorn.org/reference/settings/>`_, you'll have to copy
and modify the file instead.

.. _systemd-configuration:

Secure configuration
====================

Since the configuration contains sensitive information (database password, etc), make sure it is not
world-readable:

.. structured-tutorial-part:: secure-configuration

SystemD configuration
=====================

When you :ref:`added SystemD services <from-source-add-systemd-services>` you also created a symlink for
:file:`/etc/django-ca/systemd.conf`. If settings there do not suit you, you can override them in
:file:`/etc/django-ca/systemd-local.conf`.

.. _from-source-add-manage-py-shortcut:

Add manage.py shortcut
======================

As optional convenience, you can create a symlink to a small wrapper script that allows you to easily run
``manage.py`` commands. In the examples below the guide assumes you created this symlink at
:file:`/usr/local/bin/django-ca`, but of course you can name the symlink anything you like:

.. structured-tutorial-part:: add-shortcut

Setup Database and static files
===============================

Populate the database and setup the static files directory:

.. structured-tutorial-part:: run-initial-manage-commands

The ``collectstatic`` command needs to run as root.

*****
Start
*****

You can now finally start the Gunicorn application server and the Celery worker (omit ``django-ca`` service if
you do not intend to run a web server):

.. structured-tutorial-part:: start

Create admin user and set up CAs
================================

Because we :ref:`created a shortcut above <from-source-add-manage-py-shortcut>` above, we can use
``django-ca`` to use **django-ca** from the command line.

.. jinja:: manage-from-source
   :file: /include/create-user.rst.jinja

Setup NGINX
===========

A web server is required for the admin interface, certificate revocation status via OCSP or CRLs and ACMEv2
(the protocol used by Let's Encrypt/certbot integration).

.. WARNING::

   While theoretically possible, do not use a local CAs ACMEv2 interface to get certificates. Any
   misconfiguration might make it impossible to retrieve a certificate!

In this setup, we'll create certificates using the CA we created above. If you want to use Let's Encrypt
certificates instead, you can have a look at our :doc:`/quickstart/docker_compose` for an example.

First, you need to install NGINX:

.. structured-tutorial-part:: install-nginx

Delete the default hostname to minimize the setup:

.. structured-tutorial-part:: nginx-basic-setup

Create a private/public key pair for NGINX to use - you could also sign the certificate using a 3rd-party
certificate authority of course:

.. structured-tutorial-part:: create-tls-key

Create DH parameters:

.. structured-tutorial-part:: create-dh-params

**django-ca** includes a template for :manpage:`envsubst(1)` that you can use. The template assumes that you
have set ``$HOSTNAME``:

.. structured-tutorial-part:: create-nginx-config

.. jinja:: guide-source-where-to-go
   :file: /include/guide-where-to-go.rst.jinja
   :header_update_levels:

******
Update
******

.. include:: /include/update_intro.rst

Downloading the new release works the same as before, but you have to remove the old symlink before creating
the new one:

.. jinja::
   :file: /include/guide-update-source.rst.jinja

Create a new virtual environment (with updated dependencies) using ``uv``:

.. code-block:: console

   root@host:~# cd /opt/django-ca/src/django-ca/
   root@host:/opt/django-ca/src/django-ca/# uv sync --no-default-groups \
   >     --all-extras --no-extra postgres

Update the database schema and static files:

.. code-block:: console

   root@host:~# django-ca migrate
   root@host:~# FORCE_USER=root django-ca collectstatic

Restart services:

.. code-block:: console

   root@host:~# systemctl restart django-ca django-ca-celery django-ca-celerybeat

Update the NGINX configuration:

.. code-block:: console

   root@host:~# envsubst < /opt/django-ca/src/django-ca/nginx/source.template \
   >     < /opt/django-ca/src/django-ca/nginx/source.template \
   >     > /etc/nginx/sites-available/django-ca.conf
   root@host:~# nginx -t
   root@host:~# systemctl restart nginx

*********
Uninstall
*********

To completely uninstall **django-ca**, stop related services and remove files that where created:

.. code-block:: console

   root@host:~# systemctl stop django-ca django-ca-celery django-ca-celerybeat
   root@host:~# systemctl disable django-ca django-ca-celery django-ca-celerybeat
   root@host:~# rm -f /etc/nginx/sites-*/django-ca.conf
   root@host:~# rm -f /var/log/nginx/$HOSTNAME*.log
   root@host:~# rm -f /usr/local/bin/django-ca
   root@host:~# rm -rf /etc/django-ca/ /opt/django-ca/ /var/log/django-ca
   root@host:~# rm -f /etc/ssl/$HOSTNAME.{key,pem}

Restart NGINX so that it no longer knows about the configurations:

.. code-block:: console

   root@host:~# systemctl restart nginx

Remove the system user:

.. code-block:: console

   root@host:~# deluser django-ca

Drop the PostgreSQL database:

.. code-block:: console

   root@host:~# sudo -u postgres psql
   postgres=# DROP DATABASE django_ca;
   DROP DATABASE
   postgres=# DROP USER django_ca;
   DROP ROLE
