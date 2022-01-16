######
Update
######

Each :doc:`installation guide <install>` includes update instructions matching the installation method used.

This document lists special update instructions when you update to a certain version.

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
