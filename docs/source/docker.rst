######
Docker
######

There is a Docker container available for **django-ca**. A docker-compose file is available to deploy the full
stack including all dependencies. 

.. _docker-compose:

******************
Use docker-compose
******************

.. versionadded:: 1.15.0

   The docker-compose.yml file was added in django-ca 1.15.0.

If you just want to run **django-ca** in a quick and efficient way, using `docker-compose
<https://docs.docker.com/compose/>`__ is the fastest and most efficient option. The stack uses nginx for
serving static files, uWSGI as WSGI application server, PostgreSQL as a database and Redis as cache and
message broker.

You can fetch tagged versions or the current development version of ``docker-compose.yml`` `from GitHub
<https://github.com/mathiasertl/django-ca/>`_.

The only environment variable you need to pass is ``DJANGO_CA_HOSTNAME`` (as it defaults to localhost),
configuring the domain where your CA should be available::

   DJANGO_CA_HOSTNAME=ca.local.example.com docker-compose up

... and visit http://ca.local.example.com (assuming you set up your DNS correctly). If you want SSL for the
admin interface (you probably should) you have to :ref:`configure nginx <docker-compose-nginx>`.

All you need now is to create a user for the web interface as well as CAs to create certificates. You have to
create the CAs in the *backend* service to be able to automatically generate CRLs and OCSP keys. You can pass
``--path=ca/shared/`` when to make its private key available to the *frontend* (= the webserver) to be able to
create keys for the intermediate CA using the web interface:

.. code-block:: console

   $ docker-compose exec backend python manage.py createsuperuser
   $ docker-compose exec backend python manage.py init_ca --pathlen=1 \
   >   root /C=AT/ST=Vienna/L=Vienna/O=Org/CN=ca.example.com
   $ docker-compose exec backend python manage.py list_cas
   6F:C8:37:15:2A:21:08:AD:BB:A8:89:4A:6A:19:03:56:37:0B:F5:1A - root
   $ docker-compose exec backend python manage.py init_ca \
   >   --path=ca/shared/ \
   >   --parent=6F:C8:37:15:2A:21:08:AD:BB:A8:89:4A:6A:19:03:56:37:0B:F5:1A \
   >   child /C=AT/ST=Vienna/L=Vienna/O=Org/CN=child.ca.example.com

You can configure django-ca using all the mechanisms described in :ref:`docker-configuration`. For more
complex configuration changes, you might want to consider `extending docker-compose.yml
<https://docs.docker.com/compose/extends/>`_. For example, to add additional YAML configuration to django-ca
itself, create an override file:

.. code-block:: yaml
   :caption: docker-compose.override.yml

   version: "3.7"
   services:
       backend:
           volumes:
               # local.yml is your additional configuration file
               - ${PWD}/local.yml:/usr/src/django-ca/ca/local.yml
           environment:
               - DJANGO_CA_SETTINGS: settings.yaml:compose.yaml:local.yml
       frontend:
           volumes:
               - ${PWD}/local.yml:/usr/src/django-ca/ca/local.yml
           environment:
               - DJANGO_CA_SETTINGS: settings.yaml:compose.yaml:local.yml


The stack uses a PostgreSQL database and the ``POSTGRES_{DB,PASSWORD,USER}`` environment variables (as well as
the variant using the ``_FILE`` suffix) are passed through, so you can configure access credentials to the
database out of the box::

   POSTGRES_PASSWORD=password123 ... docker-compose up

.. _docker-compose-nginx:

Configure nginx
===============

If you want to change the nginx configuration (for example, to add TLS to your setup), you can override
``/etc/nginx/conf.d/default.template`` as a custom volume.

.. NOTE::

   Please note that various services (like OCSP and CRL lists) typically *have to* be available via HTTP and
   not HTTPS. You cannot completely disable HTTP via port 80 unless you do not need any certificate revocation
   services.

.. code-block:: yaml
   :caption: docker-compose.override.yml

   version: "3.7"
   services:
       ports:
           - 443:443
       webserver:
           volumes: ${PWD}/default.template:/etc/nginx/conf.d/default.template

... where ``${PWD}/default.template`` would be the custom site configuration configuration. Note that via
``envsubst``, this file can use environment variables for configuration as described in the `Docker image
documentation <https://hub.docker.com/_/nginx>`_:

.. code-block:: nginx
   :caption: default.template

   upstream django_ca_frontend {
      server frontend:8000;
   }
   
   server {
      listen       ${NGINX_PORT} default_server;
      server_name  ${NGINX_HOST};

      # other directives...
   }

   server {
      listen       443 default_server;
      server_name  ${NGINX_HOST};

      # TLS configuration:
      ssl_certificate ...;
      ssl_certificate_key ...;

      # other directives...
   }


**********
Use Docker
**********

You may want to use the Docker image verbatim for a sleeker setup that uses SQLite3 as a database and no
cache, no message broker and no other fancy stuff.

Assuming you have Docker installed, simply start the docker container with::

   docker run --name=django-ca -p 8000:8000 mathiasertl/django-ca

You still need the shell to create one or more root CAs. For the admin
interface, we also create a superuser::

   docker exec -it django-ca python manage.py createsuperuser
   docker exec -it django-ca python manage.py init_ca \
      example /C=AT/ST=Vienna/L=Vienna/O=Org/CN=ca.example.com

... and visit http://localhost:8000/admin/.

.. _docker-configuration:

*************
Configuration
*************

You can configure django-ca using either environment variables or additional configuration files. The included
uWSGI server can also be configured by using different ``.ini`` configuration files.  You can reuse the
environment variables used by the PostgreSQL and MySQL/MariaDB Docker containers to set up database access.
You can also use Docker Secrets to configure Djangos "Secret Key".

If you use a plain Docker container, you can pass configuration as described below. If you :ref:`use
docker-compose <docker-compose>`, you probably need to extend the default configuration as described above.

Use environment variables
=========================

Every environment variable passed to the container that starts with ``DJANGO_CA_`` is loaded as a normal
setting::

   docker run -e DJANGO_CA_CA_DIGEST_ALGORITHM=sha256 ...

Use configuration files
=======================

The Docker image is able to load additional YAML configuration files for more complex (and reproducible)
configuration changes. For example, if you create a file ``/etc/django-ca/settings.yaml``:

.. code-block:: YAML
   :caption: /etc/django-ca/settings.yaml

   # Certificates expire after ten years, default profile is "server":
   CA_DEFAULT_EXPIRES: 3650
   CA_DEFAULT_PROFILE: server

   # The standard Django DATABASES setting, see Django docs:
   DATABASES:
      default:
         ENGINE: ...


For django-ca to use the new configuration file, you need to extend the ``DJANGO_CA_SETTINGS`` environment
variable::

   docker run -v /etc/django-ca/:/etc/django-ca -e DJANGO_CA_SETTINGS=settings.yaml:/etc/django-ca/settings.yaml ...

uWSGI
=====

The container starts a `uWSGI instance <https://uwsgi-docs.readthedocs.io/>`_ to let you use the admin
interface. To replace the simple default configuration for something else, you can pass
``DJANGO_CA_UWSGI_INI`` as environment variable to set a different location::

   docker run -v /etc/django-ca/:/etc/django-ca \
      -e DJANGO_CA_UWSGI_INI=/etc/django-ca/uwsgi.ini ...

The docker container comes with different ini files, each located in ``/usr/src/django-ca/uwsgi/``:

============== ===============================================================================================
config         Description
============== ===============================================================================================
standalone.ini **Default**. Serves plain HTTP on port 8000, including static files. 
               Suitable for basic setups.
uwsgi.ini      Serves the uwsgi protocol supported by NGINX and Apache. Does not serve static files, has three
               worker processes.
============== ===============================================================================================

You can also always pass additional parameters to uWSGI using the ``DJANGO_CA_UWSGI_PARAMS`` environment
variable. For example, to start six worker processes, simply use::

   docker run -v /etc/django-ca/:/etc/django-ca \
      -e DJANGO_CA_UWSGI_PARAMS="--processes=6" ...

Use NGINX or Apache
-------------------

In more professional setups, uWSGI will not serve HTTP directly, but a webserver like Apache or NGINX will
be a proxy to uWSGI communicating via a dedicated protocol. Usually, the webserver serves static files
directly and not via uWSGI.

.. NOTE:: uWSGI supports a variety of webservers: https://uwsgi-docs.readthedocs.io/en/latest/WebServers.html

First, you need to create a directory that you can use as a `Docker volume
<https://docs.docker.com/storage/volumes/>`_ that will contain the static files that are served by the
webserver.  Note that the process in the container runs with uid/gid of 9000 by default::

   sudo mkdir /usr/share/django-ca
   sudo chown 9000:9000 /usr/share/django-ca

Now configure your webserver appropriately, e.g. for NGINX:

.. code-block:: nginx

   server {
       # ... everything else

       location / {
           uwsgi_pass 127.0.0.1:8000;
           include uwsgi_params;
       }

       location /static/ {
           alias /home/mati/git/mati/django-ca/static/static/;
       }
   }


Now all that's left is to start the container with that volume and set ``DJANGO_CA_UWSGI_INI`` to a different
ini file (note that this file is included in the container, see above)::

   docker run \
      -e DJANGO_CA_UWSGI_INI=/usr/src/django-ca/uwsgi/uwsgi.ini \
      -p 8000:8000 --name=django-ca \
      -v /usr/share/django-ca:/usr/share/django-ca \
      django-ca

Note that ``/usr/share/django-ca`` on the host will now contain the static files served by your webserver. If
you configured NGINX on port 80, you can now visit e.g. http://localhost/admin/ for the admin interface.

Database configuration
======================
 
You can use the environment variables used by the `PostgreSQL <https://hub.docker.com/_/postgres>`_ and `MySQL
<https://hub.docker.com/_/mysql>`_/`MariaDB <https://hub.docker.com/_/mariadb>`_ images to set up database
access. This also works for the variables using the ``_FILE`` suffix (e.g. for Docker Secrets)::

   docker run -e POSTGRES_PASSWORD=password123 ...

Note that as described above, the default ``docker-compose.yml`` also supports these variables::

   POSTGRES_PASSWORD=password123 ... docker-compose up

Djangos SECRET_KEY
==================

Django uses a `SECRET_KEY <https://docs.djangoproject.com/en/3.0/ref/settings/#secret-key>` used in some
signing operations. Note that this key is *never* used by **django-ca** itself.

By default, a random key will be generated on startup, so you do not have to do anything if you're happy with
that. If you want to pass a custom key, you can use the ``DJANGO_CA_SECRET_KEY`` environment variable (as
described above).

You can also use `Docker Secrets <https://docs.docker.com/engine/swarm/secrets/>`_ and pass the
``DJANGO_CA_SECRET_KEY_FILE`` to read the secret from the file. 

Run as different user
=====================

It is possible to run the uWSGI instance inside the container as a different user, *but* you have to make sure
that ``/var/lib/django-ca/`` and ``/usr/share/django-ca/`` are writable by that user. 

.. WARNING:: 

   ``/var/lib/django-ca/`` contains all sensitive data including CA private keys and login credentials to the
   admin interface. Make sure you protect this directory!

Assuming you want to use uid 3000 and gid 3001, set up appropriate folders on the host::

   mkdir /var/lib/django-ca/ /usr/share/django-ca/
   chown 3000:3001 /var/lib/django-ca/ /usr/share/django-ca/
   chmod go-rwx /var/lib/django-ca/

If you want to keep any existing data, you now must copy the data for ``/var/lib/django-ca/`` in the container
to the one on the host.

Now you can run the container with the different uid/gid::

   docker run \
      -p 8000:8000 --name=django-ca \
      -v /usr/share/django-ca:/usr/share/django-ca \
      -v /var/lib/django-ca:/var/lib/django-ca \
      --user 3000:3001 \
      django-ca


************************
Build your own container
************************

If you want to build the container by yourself, simply clone the repository and execute::

   DOCKER_BUILDKIT=1 docker build -t django-ca .
