######
Update
######

Each :doc:`installation guide <install>` includes backup and update instructions matching the installation
method used.

This document lists special update instructions when you update to a certain version.

.. _update_124:

*****************************
Update from 1.24.0 or earlier
*****************************

Update notes when upgrading to 1.25.0.

Renamed command-line arguments
==============================

To make the interface more consistent, some command-line arguments have been renamed. Old versions will
continue to work until ``django-ca==1.27.0``.

===================== ===================================
old option            new option
===================== ===================================
``--issuer-url``      ``--sign-ca-issuer``
``--issuer-alt-name`` ``--sign-issuer-alternative-name``
``--crl-url``         ``--sign-crl-full-name``
``--ocsp-url``        ``--sign-ocsp-responder``
``--ca-ocsp-url``     ``--ocsp-responder``
``--ca-issuer-url``   ``--ca-issuer``
===================== ===================================

So if your old invocation looked like this:

.. code-block:: console

   $ python manage.py init_ca --crl-url ... --ocsp-url ... ...

instead use:

.. code-block:: console

   $ python manage.py init_ca --sign-crl-full-name ... --ocsp-responder ... ...

.. _update_123:

*****************************
Update from 1.23.0 or earlier
*****************************

Update notes when upgrading to 1.24.0.

.. _switch-use-tz:

Switch to ``USE_TZ=True`` by default
====================================

The `USE_TZ <https://docs.djangoproject.com/en/4.2/ref/settings/#std-setting-USE_TZ>`_ was set to ``True`` in
``django-ca==1.24.0``. This affects you if you if:

* use the full Django project (so you :doc:`installed from source <quickstart_from_source>`, use
  :doc:`docker <docker>` or :doc:`docker compose <quickstart_docker_compose>`)
* **AND** use a database *other then* PostgreSQL (so e.g. MySQL or SQLite3).

If *both* conditions are true for you, you should convert timestamps stored in the database to UTC. If you
skip this step, timestamps stored in the database will shift by the offset from UTC of the default timezone.

The default is ``Europe/Vienna``, so the shift is either one or two hours in this case. This affects stored
expiry times, so certificates authorities and certificates will be considered as expired either too early or
to late. ACME orders will also be affected by the shift, so any order made during upgrade will throw an error.

.. WARNING::

  Invoking the below command multiple times will shift timestamps as many times, causing corrupt timestamps.

You can convert timestamps using a single ``manage.py`` command:

.. code-block:: console

   $ manage.py convert_timestamps

.. _cli-1.24.0-updates:

Command-line tools
==================

* :command:`manage.py init_ca`: The ``--pathlen`` and ``--no-pathlen`` parameters are replaced with
  ``--path-length`` and ``--no-path-length``. Old parameter names will work until ``django-ca==1.25.0``.
* :command:`manage.py sign_cert`: The ``--key-usage`` option is split into the ``--key-usage`` and
  ``--key-usage-non-critical`` option. The ``--key-usage`` takes multiple arguments (instead of a
  comma-separated list).

  New, since ``django==1.24.0``:

  .. code-block:: console

     $ manage.py sign_cert \
     >     --key-usage keyAgreement keyEncipherment

  Before, in earlier versions:

  .. code-block:: console

     $ manage.py sign_cert --key-usage critical,keyAgreement,keyEncipherment

* :command:`manage.py sign_cert`: The ``--ext-key-usage`` option is split into the ``--extended-key-usage``
  and ``--extended-key-usage-critical`` option. The ``--extended-key-usage`` takes multiple arguments (instead
  of a comma-separated list) and also allows you to pass dotted strings for OIDs unknown to django-ca.

  New, since ``django==1.24.0``:

  .. code-block:: console

     $ manage.py sign_cert \
     >     --extended-key-usage clientAuth serverAuth \
     >     --extended-key-usage-critical

  Before, in earlier versions:

  .. code-block:: console

     $ manage.py sign_cert --ext-key-usage critical,clientAuth,serverAuth

* :command:`manage.py sign_cert`: The ``--tls-feature`` option is split into the ``--tls-feature``
  and ``--tls-feature-critical`` option. The ``--tls-feature-usage`` takes multiple arguments (instead of a
  comma-separated list) and also allows you to pass dotted strings for OIDs unknown to django-ca.

  New, since ``django==1.24.0``:

  .. code-block:: console

     $ manage.py sign_cert \
     >     --tls-feature status_request \
     >     --tls-feature-critical

  Before, in earlier versions:

  .. code-block:: console

     $ manage.py sign_cert --tls-feature critical,status_request

Python API
==========

* :py:func:`CertificateAuthority.objects.init() <django_ca.managers.CertificateAuthorityManager.init>`:

  * The ``pathlen`` argument to was renamed to ``path_length``.
  * The ``ca_ocsp_url`` and ``ca_issuer_url`` parameters should now be list of strings. Support for passing
    bare strings will be removed in ``django-ca==1.25.0``.


.. _update_121:

*****************************
Update from 1.20.0 or earlier
*****************************

.. _update_121-docker-compose:

docker compose
==============

In the configuration of 1.20.0 and earlier, the PostgreSQL container does not store data on a named volume.
This means that the database would be lost if the container is removed. This does **not** happen during the
reboot of a server or during the normal upgrade procedure. None the less, it is still safer to use named
volumes to store data, so the docker compose setup starting with 1.21.0 uses named volumes for PostgreSQL (and
also Redis).

If you perform the normal update procedure, no data is lost, but you will receive a warning about the services
using data from the previous container:

.. code-block:: console

   $ docker compose up -d
   Recreating django-ca_db_1 ...
   Recreating django-ca_cache_1 ...
   WARNING: Service "db" is using volume "/var/lib/postgresql/data" from the previous container. Host mapping
   "django-ca_pgdata" has no effect. Remove the existing containers (with `docker compose rm db`) to use the host volume mapping.
   ...

To switch to named volumes, create a database backup, remove and recreate the `db` container with the new
configuration and import the backup again. While possible, these instructions do not backup Redis data, since
it is only a cache.

First, stop containers that might access the database:

.. code-block:: console

   $ docker compose stop frontend
   $ docker compose stop backend

Second, create a dump of the database (Note: if you use a different database name or username, adapt
accordingly):

.. code-block:: console

   $ docker compose exec db pg_dump -U postgres postgres > db.sql

Third, you might want to check if :file:`db.sql` contains a valid database dump.

Fourth, remove the containers:

.. code-block:: console

   $ docker compose rm -sf cache db

Fifth, if you haven't already, update your :file:`docker-compose.yml`. To verify you have the named volumes,
check that both the ``db`` and ``cache`` services have a ``volume`` with them. It does not matter if you have
updated the file before performing the above steps.

Sixth, start the ``db`` container again (it will be recreated) and import the dump.

.. code-block:: console

   $ docker compose up -d db
   $ docker compose exec -T db psql -U postgres postgres < db.sql


Seventh, start all other containers:

.. code-block:: console

   $ docker compose up -d

And finally, verify success - you should see your CAs:

.. code-block:: console

   $ docker compose exec backend manage list_cas
   ...

.. _update_119:

***************************
Update from 1.18 or earlier
***************************

If you use **docker compose**, you need to backup private keys and update your :file:`docker-compose.yml`
before upgrading. If you don't private keys will be lost. The change to :file:`docker-compose.yml` will make
sure that keys will survive the next update.

**First,** you need to copy your private keys to a permanently stored location. If you do not have any keys in
either the backend or frontend, ``mv`` will throw an error, which is of course fine in this case:

.. code-block:: console

   $ docker compose exec backend mkdir -p /var/lib/django-ca/certs/ca/shared/backend/
   $ docker compose exec backend /bin/sh -c "cp /var/lib/django-ca/certs/ca/*.key /var/lib/django-ca/certs/ca/shared/backend/"
   $ docker compose exec frontend mkdir -p /var/lib/django-ca/certs/ca/shared/frontend/
   $ docker compose exec frontend /bin/sh -c "cp /var/lib/django-ca/certs/ca/*.key /var/lib/django-ca/certs/ca/shared/frontend/"

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

   $ docker compose pull
   $ docker compose up -d

**Finally,** move the keys from the temporary location to the primary location:

.. code-block:: console

   $ docker compose exec backend /bin/sh -c "mv /var/lib/django-ca/certs/ca/shared/backend/*.key /var/lib/django-ca/certs/ca/"
   $ docker compose exec backend rmdir /var/lib/django-ca/certs/ca/shared/backend/
   $ docker compose exec frontend /bin/sh -c "mv /var/lib/django-ca/certs/ca/shared/frontend/*.key /var/lib/django-ca/certs/ca/"
   $ docker compose exec frontend rmdir /var/lib/django-ca/certs/ca/shared/frontend/

.. _update_114:

***************************
Update from 1.17 or earlier
***************************

Please see documentation for previous versions on documentation how to upgrade.
