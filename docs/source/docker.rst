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

The container starts a `uWSGI webserver <https://uwsgi-docs.readthedocs.io/>`_ to let you use the admin
interface. To replace the simple default configuration for something else, you can pass
``DJANGO_CA_UWSGI_INI`` as environment variable to set a different location::

   docker run -v /etc/django-ca/:/etc/django-ca \
      -e DJANGO_CA_UWSGI_INI=/etc/django-ca/uwsgi.ini ...

************************
Build your own container
************************

If you want to build the container by yourself, simply clone the repository and
execute::

   docker build -t django-ca .
