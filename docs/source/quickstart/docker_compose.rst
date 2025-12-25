##############################
Quickstart with Docker Compose
##############################

.. _docker-compose:

.. structured-tutorial:: compose/tutorial.yaml

This guide provides instructions for running your own certificate authority using **docker compose**. This is
the quickest and easiest way to run django-ca, especially if you do not care to much about custom
configuration or extending django-ca.

This tutorial will give you a CA with

* A root and intermediate CA.
* ACMEv2 support (= get certificates using certbot).
* A browsable admin interface and a REST API.
* Certificate revocation using CRLs and OCSP.
* ACMEv2, admin interface and REST API are served with HTTPS using Let's Encrypt certificates.

.. NOTE::

    This tutorial uses `structured-tutorials <https://structured-tutorials.readthedocs.io/en/latest/>`_.

    This means that the documentation you see here is rendered from a configuration file and can also be run
    locally to verify correctness and completeness.

************
Requirements
************

.. jinja::
   :file: /include/guide-requirements.rst.jinja
   :header_update_levels:

Required software
=================

To run **django-ca**, you need Docker (at least version 19.03.0) and Docker Compose (at least version 1.28.0).
You also need certbot to acquire Let's Encrypt certificates for the admin interface. OpenSSL is used to
generate the DH parameter file. On Debian/Ubuntu, simply do:

.. structured-tutorial-part:: install-dependencies

For a different OS, please read `Install Docker <https://docs.docker.com/engine/install/>`_, `Install
docker compose <https://docs.docker.com/compose/install/>`_ and `Get certbot
<https://certbot.eff.org/docs/install.html>`_.

If you want to run docker(-compose) as a regular user, you need to add your user to the ``docker`` group and
log in again:

.. structured-tutorial-part:: add-docker-group

*****************
Get configuration
*****************

.. NOTE::

   Because of how **Docker Compose** works, it is better to put the file in a sub-directory and `not` directly
   into your home directory. We assume you put all files into ``~/ca/`` from now on:

   .. structured-tutorial-part:: create-ca-directory

To run **django-ca**, you'll need a couple of files:

* :ref:`dhparam.pem <quickstart-compose-dhparam.pem>`, the DH parameters (required for TLS
  connections).
* :ref:`conf/ <quickstart-compose-config-files>`, a directory with YAML configuration files.
* :ref:`compose.yaml <quickstart-compose-compose.yaml>`, the configuration for Docker Compose.
* :ref:`compose.override.yaml <quickstart-compose-compose.override.yaml>`, system-local configuration
  overrides for Docker Compose.
* :ref:`.env <quickstart-compose-.env>`, the environment file for Docker Compose.
* :ref:`nginx-reload.sh <quickstart-compose-nginx-reload.sh>`, a certbot *deploy hook* to reload NGINX after
  certificate renewal.

Read the sections below how to retrieve or generate all these files.

.. _quickstart-compose-dhparam.pem:

Generate DH parameters
======================

The TLS configuration requires that you generate a DH parameter file, which used by some TLS ciphers. You can
generate it with:

.. structured-tutorial-part:: generate-dh-params

.. _quickstart-compose-config-files:

Add configuration files
=======================

.. versionchanged:: 2.5.0

    Previous versions documented a single file in ``~/ca/``, the new style allows you to split the
    configuration into multiple files.

**django-ca** is configured via a YAML configuration files. It is not strictly required, as the defaults are
fine in most cases. Creating at least an empty file is recommended, as it will make any future changes easier.

.. NOTE::

   Do not set ``CA_DEFAULT_HOSTNAME`` and ``CA_URL_PATH`` here! They are set in `.env
   <quickstart-docker-compose-.env>`_, as the NGINX container also uses them.

First, simply create a configuration directory:

.. structured-tutorial-part:: mkdir-conf

You can create any number of files in that directory, and they will be read in alphabetical order. Here we add
an example that just enables the :doc:`/rest_api`:

.. structured-tutorial-part:: create-config-rest

You can configure any `Django setting <https://docs.djangoproject.com/en/dev/ref/settings/>`_ or any of the
:doc:`custom settings </settings>` here. See :ref:`settings-yaml-configuration` for more examples. Almost
all settings can be changed later, if that is not the case, the settings documentation mentions it.

.. _quickstart-compose-compose.yaml:

Add ``compose.yaml``
====================

Docker Compose needs a configuration file, :download:`compose.yaml </_files/compose.yaml>`. You
can also download the file for other versions `from github
<https://github.com/mathiasertl/django-ca/blob/master/compose.yaml>`_.

You can also get versions for specific versions of **django-ca** from the table below, which also shows
bundled third-party Docker images.

.. WARNING::

   When updating, check if the PostgreSQL version has been updated. If yes, see :ref:`postgresql_update`
   for upgrade instructions.

.. Keep no more then 10 releases in this table.

==================================================================================== ===== ========== ========
Version                                                                              Redis PostgreSQL NGINX
==================================================================================== ===== ========== ========
`2.5.0 <https://github.com/mathiasertl/django-ca/blob/2.4.0/compose.yaml>`_          **8** 16         **1.28**
`2.4.0 <https://github.com/mathiasertl/django-ca/blob/2.4.0/compose.yaml>`_          7     16         1.26
`2.3.0 <https://github.com/mathiasertl/django-ca/blob/2.3.0/compose.yaml>`_          7     16         1.26
`2.2.0 <https://github.com/mathiasertl/django-ca/blob/2.2.0/compose.yaml>`_          7     16         1.26
`2.1.1 <https://github.com/mathiasertl/django-ca/blob/2.1.1/docker-compose.yml>`_    7     16         1.26
`2.1.0 <https://github.com/mathiasertl/django-ca/blob/2.1.0/docker-compose.yml>`_    7     16         1.26
`2.0.0 <https://github.com/mathiasertl/django-ca/blob/2.0.0/docker-compose.yml>`_    7     16         1.26
`1.29.0 <https://github.com/mathiasertl/django-ca/blob/1.29.0/docker-compose.yml>`_  7     16         1.24
`1.28.0 <https://github.com/mathiasertl/django-ca/blob/1.28.0/docker-compose.yml>`_  7     **16**     1.24
`1.27.0 <https://github.com/mathiasertl/django-ca/blob/1.27.0/docker-compose.yml>`_  7     12         1.24
==================================================================================== ===== ========== ========

Note that until ``django-ca==2.1.1``, this file was called ``docker-compose.yml``.

.. _quickstart-compose-compose.override.yaml:

Add ``compose.override.yaml``
=============================

The default :file:`compose.yaml` does not offer HTTPS, because too many details (cert location, etc.)
are different from system to system. We need to add a `compose override file
<https://docs.docker.com/compose/how-tos/multiple-compose-files/merge/>`_ to open the port and map the
directories with the certificates into the container.  Simply add a file called :file:`compose.override.yaml`
next to your main configuration file:

.. structured-tutorial-part:: copy-compose-override-yaml

This will work if you get your certificates using ``certbot`` or a similar client. If your private key in
public key chain is named different, you can set ``NGINX_PRIVATE_KEY`` and ``NGINX_PUBLIC_KEY`` in your
:file:`.env` file below.

.. _quickstart-compose-.env:

Add ``.env`` file
=================

Some settings in **django-ca** can be configured with environment variables (except where a more complex
structure is required). Simply create a file called :file:`.env` next to :file:`compose.yaml`.

For a quick start, there are only a few variables you need to specify:

.. structured-tutorial-part:: copy-env

.. _quickstart-compose-nginx-reload.sh:

Add ``nginx-reload.sh`` file
============================

:file:`nginx-reload.sh` is a certbot deployment hook that will reload the web server when the certbot
certificate is renewed:

.. structured-tutorial-part:: copy-nginx-reload

Certbot requires the script to be executable:

.. structured-tutorial-part:: chmod-nginx-reload

Recap
=====

By now, you should have *five* files and *one* directory in ``~/ca/``:

.. structured-tutorial-part:: ls-recap

.. _quickstart-compose-get-initial-certificates:

************************
Get initial certificates
************************

Some endpoints of the CA (ACMEv2, REST API and the admin interface) are available via HTTPS. In our
tutorial, we will use Let's Encrypt certificates for maximum compatibility for clients.

You could also use certificates from a CA managed by **django-ca** itself, but such a setup could lead to a
situation where endpoints are no longer working due to faulty (e.g. expired) certificates, but you need
working endpoints to renew them.

Retrieving initial certificates must be done `before` you run **docker compose**, as both bind to port 80
(HTTP):

.. structured-tutorial-part:: get-certificates-with-certbot

The above example uses the ``standalone`` plugin to fulfill a `HTTP-01 challenge type <https://letsencrypt
.org/docs/challenge-types/>`_. This challenge requires your server to export port 80 to the internet. If
that does not work for you but you still want to use Let's Encrypt, you can use any of the `many plugins
<https://eff-certbot.readthedocs.io/en/stable/using.html#third-party-plugins>`_.

*************
Start your CA
*************

Now, you can start **django-ca** for the first time. Inside the folder with all your configuration, run
**docker compose** (and verify that everything is running):

.. structured-tutorial-part:: start-compose

By now, you should be able to see the admin interface (but not log in yet - you haven't created a user yet).
Simply go to https://ca.example.com/admin/.

Verify setup
============

You can run the deployment checks for your setup, which should not return any issues:

.. structured-tutorial-part:: run-manage-check

Create admin user and set up CAs
================================

Inside the backend container, ``manage`` is an alias for ``manage.py``.

.. jinja:: manage-in-docker-compose
   :file: /include/create-user.rst.jinja

.. _docker-compose-use-ca:

.. jinja:: guide-docker-compose-where-to-go
   :file: /include/guide-where-to-go.rst.jinja
   :header_update_levels:

*****************************
Automatic certificate renewal
*****************************

If you used the ``certbot certonly --standalone`` to retrieve Let's Encrypt certificates (:ref:`see above
<quickstart-compose-get-initial-certificates>`), you still need to configure automatic certificate renewal.
The current setup will not work, as port 80 is now occupied by nginx. Tell certbot to renew certificates
using the :spelling:ignore:`"webroot"` plugin instead:

.. structured-tutorial-part:: setup-certbot-automatic-renewal

If you used any other ACMEv2 authentication method (e.g. a DNS-based setup), you probably don't need to do
anything here.

.. _docker-compose-backup:

******
Backup
******

To backup your data, you need to store the PostgreSQL database and the private key files for your certificate
authorities.

If possible for you, you can first stop the ``frontend`` and ``backend`` containers to make absolutely sure
that you have a consistent backup:

.. code-block:: console

   user@host:~/ca/$ docker compose stop frontend
   user@host:~/ca/$ docker compose stop backend

Create a database backup:

.. code-block:: console

   user@host:~/ca/$ docker compose exec db pg_dump -U postgres postgres > db.backup.sql

Backing up Docker volumes is not as straight forward as maybe it should be, please see `the official
documentation <https://docs.docker.com/storage/volumes/#backup-restore-or-migrate-data-volumes>`_ for more
information.

You should always backup ``/var/lib/django-ca/certs/`` from both the ``backend`` and the ``frontend``
container.

Here is an example that should work for the ``backend`` container.:

.. code-block:: console

   user@host:~/ca/$ docker run -it --rm --volumes-from `basename $PWD`_backend_1 \
   >     -v $(pwd):/backup ubuntu tar czf /backup/backend.tar.gz /var/lib/django-ca/certs/
   user@host:~/ca/$ tar tf backend.tar.gz
   var/lib/django-ca/certs/
   var/lib/django-ca/certs/ca/
   var/lib/django-ca/certs/ca/1BBB69C1D3B64AB5EF39C2946015F57A0FB04107.key
   var/lib/django-ca/certs/ca/shared/
   var/lib/django-ca/certs/ca/shared/secret_key
   ...

******
Update
******

.. include:: /include/update_intro.rst

.. WARNING::

   * **Updating from django-ca 1.28.0 or earlier?** Please see :ref:`postgresql_update`.
   * **Updating from django-ca 1.18.0 or earlier?** Please see :ref:`update_119`.

Remember to :ref:`backup your data <docker-compose-backup>` before you perform any update.

In general, updating django-ca is done by getting the :ref:`latest version of compose.yaml
<quickstart-compose-compose.yaml>` and then simply recreating the containers:

.. code-block:: console

   user@host:~/ca/$ curl -O https://.../compose.yaml
   user@host:~/ca/$ docker compose up -d

.. _postgresql_update:

PostgreSQL update
=================

When a new version :file:`compose.yaml` includes a new version of PostgreSQL, you have to take some
extra steps to migrate the PostgreSQL database.

**Before you upgrade**, back up your PostgreSQL database as usual:

.. code-block:: console

   user@host:~/ca/$ docker compose down
   user@host:~/ca/$ docker compose up -d db
   user@host:~/ca/$ docker compose exec db pg_dump -U postgres -d postgres > backup.sql

Now update :file:`compose.yaml` but then **only start the database**:

.. code-block:: console

   user@host:~/ca/$ curl -O https://.../compose.yaml
   user@host:~/ca/$ docker compose up -d db

Once the database is started, update the database with data from your backup and normally start your setup:

.. code-block:: console

   user@host:~/ca/$ cat backup.sql | docker compose exec -T db psql -U postgres -d postgres
   user@host:~/ca/$ docker compose up -d

Forgot to backup?
-----------------

If you forgot to backup your database and started the update already, don't panic. Whenever we update the
PostgreSQL version, we use a a new Docker volume. You should be able to reset :file:`compose.yaml` and
then proceed to do the backup normally.
