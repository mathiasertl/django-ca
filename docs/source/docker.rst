######
Docker
######

There is a **django-ca** Docker container available.

Assuming you have Docker installed, simply start the docker container with::

   docker run --name=django-ca -p 8000:8000 mathiasertl/django-ca

You still need the shell to create one or more root CAs. For the admin
interface, we also create a superuser::

   docker exec -it django-ca python ca/manage.py createsuperuser
   docker exec -it django-ca python ca/manage.py init_ca \
      example /C=AT/ST=Vienna/L=Vienna/O=Org/CN=ca.example.com

... and visit http://localhost:8000/admin/.

*************
Configuration
*************

Every environment variable passed to the container that starts with ``DJANGO_CA_`` is loaded as a normal
setting::

   docker run -e DJANGO_CA_CA_DIGEST_ALGORITHM=sha256 ...

This however only works for settings that are supposed to be a string. For more complex settings, you can pass
a YAML configuration file. For example, if you create a file ``/etc/django-ca/settings.yaml``:

.. code-block:: YAML

   # Certificates expire after ten years, default profile is "server":
   CA_DEFAULT_EXPIRES: 3650
   CA_DEFAULT_PROFILE: server

   # The standard Django DATABASES setting, see Django docs:
   DATABASES:
      default:
         ENGINE: ...


And then start the container with::

   docker run -v /etc/django-ca/:/etc/django-ca \
      -e DJANGO_CA_SETTINGS=/etc/django-ca/settings.yaml ...

... the container will load your settings file.

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
===================

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

If you want to build the container by yourself, simply clone the repository and
execute::

   docker build -t django-ca .
