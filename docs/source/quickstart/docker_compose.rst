##############################
Quickstart with Docker Compose
##############################

.. _docker-compose:

This guide provides instructions for running your own certificate authority using **docker compose**. This is
the quickest and easiest way to run django-ca, especially if you do not care to much about custom
configuration or extending django-ca.

This tutorial will give you a CA with

* A root and intermediate CA.
* A browsable admin interface, protected by TLS (using Let's Encrypt certificates).
* Certificate revocation using CRLs and OCSP.
* (Optional) ACMEv2 support (= get certificates using certbot).

.. jinja:: requirements-in-docker-compose
   :file: /include/guide-requirements.rst.jinja
   :header_update_levels:

Required software
=================

To run **django-ca**, you need Docker (at least version 19.03.0) and Docker Compose (at least version 1.27.0).
You also need certbot to acquire Let's Encrypt certificates for the admin interface. OpenSSL is used to
generate the DH parameter file. On Debian/Ubuntu, simply do:

.. code-block:: console

   user@host:~$ sudo apt update
   user@host:~$ sudo apt install docker.io docker-compose certbot openssl

For a different OS, please read `Install Docker <https://docs.docker.com/engine/install/>`_, `Install
docker compose <https://docs.docker.com/compose/install/>`_ and `Get certbot
<https://certbot.eff.org/docs/install.html>`_.

.. include:: /include/docker-regular-user.rst

************************
Get initial certificates
************************

Use certbot to acquire initial certificates. This must be done `before` you run **docker compose**, as both
bind to port 80 (HTTP).

.. code-block:: console

   user@host:~$ sudo certbot certonly --standalone -d ca.example.com
   ...
   user@host:~$ sudo ls /etc/letsencrypt/live/ca.example.com
   README  cert.pem  chain.pem  fullchain.pem  privkey.pem

.. _docker-compose.yml:

*****************
Get configuration
*****************

Docker-compose needs a configuration file, :download:`docker-compose.yml </_files/docker-compose.yml>`. You
can also download the file for other versions `from github
<https://github.com/mathiasertl/django-ca/blob/master/docker-compose.yml>`_.

.. NOTE::

   Because of how **Docker Compose** works, it is better to put the file in a sub-directory and `not` directly
   into your home directory. We assume you put all files into ``~/ca/`` from now on.

You can also get versions for specific versions of **django-ca** from the table below, which also shows
bundled third-party Docker images.

.. WARNING::

   When updating, check if the PostgreSQL version has been updated. If yes, see :ref:`postgresql_update`
   for upgrade instructions.

==================================================================================== ===== ========== =======
Version                                                                              Redis PostgreSQL NGINX
==================================================================================== ===== ========== =======
`2.1.1 <https://github.com/mathiasertl/django-ca/blob/2.0.0/docker-compose.yml>`_    7     16         1.26
`2.1.0 <https://github.com/mathiasertl/django-ca/blob/2.0.0/docker-compose.yml>`_    7     16         1.26
`2.0.0 <https://github.com/mathiasertl/django-ca/blob/2.0.0/docker-compose.yml>`_    7     16         1.26
`1.29.0 <https://github.com/mathiasertl/django-ca/blob/1.29.0/docker-compose.yml>`_  7     16         1.24
`1.28.0 <https://github.com/mathiasertl/django-ca/blob/1.28.0/docker-compose.yml>`_  7     **16**     1.24
`1.27.0 <https://github.com/mathiasertl/django-ca/blob/1.27.0/docker-compose.yml>`_  7     12         1.24
`1.26.0 <https://github.com/mathiasertl/django-ca/blob/1.26.0/docker-compose.yml>`_  7     12         1.24
`1.25.0 <https://github.com/mathiasertl/django-ca/blob/1.25.0/docker-compose.yml>`_  7     12         **1.24**
`1.24.0 <https://github.com/mathiasertl/django-ca/blob/1.24.0/docker-compose.yml>`_  7     12         1.23
`1.23.0 <https://github.com/mathiasertl/django-ca/blob/1.23.0/docker-compose.yml>`_  7     12         **1.23**
`1.22.0 <https://github.com/mathiasertl/django-ca/blob/1.22.0/docker-compose.yml>`_  **7** 12         1.20
`1.21.0 <https://github.com/mathiasertl/django-ca/blob/1.21.0/docker-compose.yml>`_  6     12         1.20
==================================================================================== ===== ========== =======

Add ``docker-compose.override.yml``
===================================

The default :file:`docker-compose.yml` does not offer HTTPS, because too many details (cert location, etc.)
are different from system to system. We need to add a `docker-compose override file
<https://docs.docker.com/compose/extends/>`_ to open the port and map the directories with the certificates
into the container.  Simply add a file called :file:`docker-compose.override.yml` next to your main
configuration file:

.. template-include:: yaml /include/quickstart_with_docker_compose/docker-compose.override.yml.jinja
   :caption: docker-compose.override.yml
   :context: quickstart-with-docker-compose

This will work if you get your certificates using ``certbot`` or a similar client. If your private key in
public key chain is named different, you can set ``NGINX_PRIVATE_KEY`` and ``NGINX_PUBLIC_KEY`` in your
:file:`.env` file below.

Add ``.env`` file
=================

Some settings in **django-ca** can be configured with environment variables (except where a more complex
structure is required). Simply create a file called :file:`.env` next to :file:`docker-compose.yaml`.

For a quick start, there are only a few variables you need to specify:

.. template-include:: bash /include/quickstart_with_docker_compose/.env.jinja
   :caption: .env
   :context: quickstart-with-docker-compose

Generate DH parameters
======================

The TLS configuration also requires that you generate a DH parameter file, used by some TLS ciphers. You can
generate it with:

.. console-include::
   :include: /include/quickstart_with_docker_compose/dhparam.yaml
   :context: quickstart-with-docker-compose
   :path: ~/ca/

Customization
=============

Although the defaults are fine for most scenarios, **django-ca** and Django itself support a wide range of
settings to customize your installation. Django has its settings documented under `Settings
<https://docs.djangoproject.com/en/4.0/ref/settings/>`_, django-ca settings are documented under :doc:`custom
settings </settings>`.

Just like when using the plain Docker container, you can configure django-ca using either environment
variables (set in e.g. ``docker-compose.override.yml``) or using an extra YAML configuration file. For more
details on how to configure the Docker container, refer to :ref:`docker-configuration`.

.. NOTE::

   In our **docker compose** setup, django-ca is used in both the ``backend`` and ``frontend`` containers.
   Make sure you configure both of them.


Configuration using a YAML configuration file
---------------------------------------------

Using an extra configuration file is the most flexible way to configure django-ca, as it allows you to update
even complex settings. It has the added advantage that **docker compose** will not recreate the containers if
you update the configuration.

As with the normal docker container, django-ca will read configuration files in
``/usr/src/django-ca/ca/conf/`` in alphabetical order, but it will also read files in the subfolder
``/usr/src/django-ca/conf/ca/compose/``, which provides configuration specific to our **docker compose**
setup.

To add a configuration file, first add a volume mapping in your ``docker-compose.override.yml``:

.. literalinclude:: /include/quickstart_with_docker_compose/docker-compose.override-localsettings-example.yml
   :language: yaml
   :caption: docker-compose.override.yml

... and then simply add a file called ``localsettings.yaml`` in your current directory, for example:

.. literalinclude:: /include/quickstart_with_docker_compose/localsettings.example.yml
   :language: yaml
   :caption: localsettings.yaml (example)

Please see :doc:`/settings` for a list of available settings and especially :ref:`settings-yaml-configuration`
for more YAML configuration examples.

Configuration using environment variables
-----------------------------------------

If you want to use environment variables for configuration, we recommend you first add them to your
``docker-compose.override.yml``, for example to `configure a different SMTP server
<https://docs.djangoproject.com/en/4.0/ref/settings/#email-host>`_ for sending out emails:

.. literalinclude:: /include/quickstart_with_docker_compose/docker-compose.override-env-example.yml
   :language: yaml
   :caption: docker-compose.override.yml

and in your ``.env`` file, set the variable:

.. code-block:: bash

   DJANGO_CA_EMAIL_HOST=smtp.example.com


Recap
=====

By now, you should have at least four files in ``~/ca/``:

.. code-block:: console

   user@host:~/ca/$ ls -A
   docker-compose.yml docker-compose.override.yml .env dhparam.pem

*************
Start your CA
*************

Now, you can start **django-ca** for the first time. Inside the folder with all your configuration, run
**docker compose** (and verify that everything is running):

.. console-include::
   :include: /include/quickstart_with_docker_compose/docker-compose-up.yaml
   :context: quickstart-with-docker-compose
   :path: ~/ca/

By now, you should be able to see the admin interface (but not log in yet - you haven't created a user yet).
Simply go to https://ca.example.com/admin/.

Verify setup
============

You can run the deployment checks for your setup, which should not return any issues:

.. console-include::
   :include: /include/quickstart_with_docker_compose/verify-setup.yaml
   :context: quickstart-with-docker-compose
   :path: ~/ca/


Create admin user and set up CAs
================================

Inside the backend container, ``manage`` is an alias for ``manage.py``.

.. jinja:: manage-in-docker-compose
   :file: /include/create-user.rst.jinja

.. _docker-compose-use-ca:

.. jinja:: guide-docker-compose-where-to-go
   :file: /include/guide-where-to-go.rst.jinja
   :header_update_levels:

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
   >     -v `pwd`:/backup ubuntu tar czf /backup/backend.tar.gz /var/lib/django-ca/certs/
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

In general, updating django-ca is done by getting the :ref:`latest version of docker-compose.yml
<docker-compose.yml>` and then simply recreating the containers:

.. code-block:: console

   user@host:~/ca/$ curl -O https://.../docker-compose.yml
   user@host:~/ca/$ docker compose up -d

.. _postgresql_update:

PostgreSQL update
=================

When a new version :file:`docker-compose.yml` includes a new version of PostgreSQL, you have to take some
extra steps to migrate the PostgreSQL database.

**Before you upgrade**, back up your PostgreSQL database as usual:

.. code-block:: console

   user@host:~/ca/$ docker-compose down
   user@host:~/ca/$ docker compose up -d db
   user@host:~/ca/$ docker compose exec db pg_dump -U postgres -d postgres > backup.sql

Now update :file:`docker-compose.yml` but then **only start the database**:

.. code-block:: console

   user@host:~/ca/$ curl -O https://.../docker-compose.yml
   user@host:~/ca/$ docker compose up -d db

Once the database is started, update the database with data from your backup and normally start your setup:

.. code-block:: console

   user@host:~/ca/$ cat backup.sql | docker compose exec -T db psql -U postgres -d postgres
   user@host:~/ca/$ docker compose up -d

Forgot to backup?
-----------------

If you forgot to backup your database and started the update already, don't panic. Whenever we update the
PostgreSQL version, we use a a new Docker volume. You should be able to reset :file:`docker-compose.yml` and
then proceed to do the backup normally.
