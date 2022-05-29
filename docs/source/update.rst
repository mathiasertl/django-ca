######
Update
######

Each :doc:`installation guide <install>` includes backup and update instructions matching the installation
method used.

This document lists special update instructions when you update to a certain version.

.. _update_121:

*************************
Update to 1.21.0 or later
*************************

.. _update_121-docker-compose:

docker-compose
==============

In the configuration of 1.20.0 and earlier, the PostgreSQL container does not store data on a named volume.
This means that the database would be lost if the container is removed. This does **not** happen during the
reboot of a server or during the normal upgrade procedure. None the less, it is still safer to use named
volumes to store data, so the docker-compose setup starting with 1.21.0 uses named volumes for PostgreSQL (and
also Redis).

If you perform the normal update procedure, no data is lost, but you will receive a warning about the services
using data from the previous container:

.. code-block:: console

   $ (django-ca) mertl@pcn97:~/git/mati/django-ca$ docker-compose up -d
   Recreating django-ca_db_1 ...
   Recreating django-ca_cache_1 ...
   WARNING: Service "db" is using volume "/var/lib/postgresql/data" from the previous container. Host mapping
   "django-ca_pgdata" has no effect. Remove the existing containers (with `docker-compo
   se rm db`) to use the host volume mapping.
   ...

To switch to named volumes, create a database backup, remove and recreate the `db` container with the new
configuration and import the backup again. While possible, these instructions do not backup Redis data, since
it is only a cache.

First, stop containers that might access the database:

.. code-block:: console

   $ docker-compose stop frontend
   $ docker-compose stop backend

Second, create a dump of the database (Note: if you use a different database name or username, adapt
accordingly):

.. code-block:: console

   $ docker-compose exec db pg_dump -U postgres postgres > db.sql

Third, you might want to check if :file:`db.sql` contains a valid database dump.

Fourth, remove the containers:

.. code-block:: console2yy

   $ docker-compose rm -sf cache db

Fifth, if you haven't already, update your :file:`docker-compose.yml`. To verify you have the named volumes,
check that both the ``db`` and ``cache`` services have a ``volume`` with them. It does not matter if you have
updated the file before performing the above steps.

Sixth, start the ``db`` container again (it will be recreated) and import the dump.

.. code-block:: console2

   $ docker-compose up -d db
   $ docker-compose exec -T db psql -U postgres postgres < db.sql


Seventh, start all other containers:

.. code-block:: console2

   $ docker-compose up -d

And finally, verify success - you should see your CAs:

.. code-block:: console

   $ docker-compose exec backend manage list_cas
   ...

.. _update_119:

*************************
Update to 1.19.0 or later
*************************

If you use **docker-compose**, you need to backup private keys and update your :file:`docker-compose.yml`
before upgrading. If you don't private keys will be lost. The change to :file:`docker-compose.yml` will make
sure that keys will survive the next update.

**First,** you need to copy your private keys to a permanently stored location. If you do not have any keys in
either the backend or frontend, ``mv`` will throw an error, which is of course fine in this case:

.. code-block:: console

   $ docker-compose exec backend mkdir -p /var/lib/django-ca/certs/ca/shared/backend/
   $ docker-compose exec backend /bin/sh -c "cp /var/lib/django-ca/certs/ca/*.key /var/lib/django-ca/certs/ca/shared/backend/"
   $ docker-compose exec frontend mkdir -p /var/lib/django-ca/certs/ca/shared/frontend/
   $ docker-compose exec frontend /bin/sh -c "cp /var/lib/django-ca/certs/ca/*.key /var/lib/django-ca/certs/ca/shared/frontend/"

Note that if you have stored private keys in any custom location with the ``--path`` argument, you need to
backup these locations as well.

**Second,** update your :file:`docker-compose.yml` file. Either get the :ref:`latest version of the file
<docker-compose.yml>`, or apply this diff:

.. code-block:: diff

   --- docker-compose.yml.orig
   +++ docker-compose.yml
   @@ -33,6 +33,7 @@ services:
                - database
                - public
            volumes:
   +            - backend_ca_dir:/var/lib/django-ca/certs/
                - shared_ca_dir:/var/lib/django-ca/certs/ca/shared/
                - ocsp_key_dir:/var/lib/django-ca/certs/ocsp/
                - shared:/var/lib/django-ca/shared/
   @@ -65,6 +66,7 @@ services:
                - frontend
            volumes:
                - static:/usr/share/django-ca/static/
   +            - frontend_ca_dir:/var/lib/django-ca/certs/
                - shared_ca_dir:/var/lib/django-ca/certs/ca/shared/
                - ocsp_key_dir:/var/lib/django-ca/certs/ocsp/
                - shared:/var/lib/django-ca/shared/
   @@ -116,6 +118,8 @@ services:
    volumes:
        shared:
        static:
   +    backend_ca_dir:
   +    frontend_ca_dir:
        shared_ca_dir:
        ocsp_key_dir:
        nginx_config:

**Third,** do a normal upgrade:

.. code-block:: console

   $ docker-compose pull
   $ docker-compose up -d

**Finally,** move the keys from the temporary location to the primary location:

.. code-block:: console

   $ docker-compose exec backend /bin/sh -c "mv /var/lib/django-ca/certs/ca/shared/backend/*.key /var/lib/django-ca/certs/ca/"
   $ docker-compose exec backend rmdir /var/lib/django-ca/certs/ca/shared/backend/
   $ docker-compose exec frontend /bin/sh -c "mv /var/lib/django-ca/certs/ca/shared/frontend/*.key /var/lib/django-ca/certs/ca/"
   $ docker-compose exec frontend rmdir /var/lib/django-ca/certs/ca/shared/frontend/

.. _update_114:

*************************
Update to 1.14.0 or later
*************************

**django-ca** has changed the layout of the :ref:`CA_PROFILES <settings-ca-profiles>`, you have to update any
any custom setting. Please see documentation for django-ca 1.16 for more detailed instructions.

The old profile settings will be supported until (and including) version 1.16.

.. _update-file-storage:

*************************
Update to 1.12.0 or later
*************************

Please see documentation for previous versions on documentation how to upgrade.
