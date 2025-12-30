#######################
Extend the Docker image
#######################

The stock Docker image can be extended in a variety of ways.

*******************
General information
*******************

The default image is based on the slim variant of the `official Python image
<https://hub.docker.com/_/python>`_. This means it is based on the current Debian stable version and the
latest Python version.

**django-ca** runs in a `virtual environment <https://docs.python.org/3/library/venv.html>`_ created with
`uv <https://docs.astral.sh/uv/>`_, but ``uv`` is not installed in the image to keep the image size to a
minimum.

***************************
Install additional packages
***************************

To install additional packages (like other third-party Django apps), you first need to install `uv in Docker
<https://docs.astral.sh/uv/guides/integration/docker/>`_. Note that the virtual environment is already active:

.. code-block:: Dockerfile
   :caption: ``Dockerfile`` for django-ca with additional Python packages

   FROM mathiasertl/django-ca

   # Install uv (see https://docs.astral.sh/uv/guides/integration/docker/#installing-uv)
   COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
   ENV UV_LINK_MODE=copy

   # Install additional packages in the django-ca virtual environment:
   RUN --mount=type=cache,target=/root/.cache/uv \
       uv pip install ...

This of course also works if you want to install your local package with ``uv pip install -e .``, you just
need to add your source code first.

To verify that you install packages correctly, build your image and try importing the Python modules you
installed:

.. code-block:: console

   $ docker build -t example .
   $ docker run --rm -it example python -c 'import ...'

*****************
Add configuration
*****************

To load additional settings for either Django, django-ca or your own django apps, simply place YAML files in
``/usr/src/django-ca/ca/conf/``. Files placed here will be loaded into the Django settings system when the
application starts. The Compose setup also loads files from ``/usr/src/django-ca/ca/conf/compose/``. If you
place files here, settings will only be loaded if started via Compose.

The locations that settings are loaded from is controlled by :ref:`settings-django-ca-settings`.

If for example you want to override a django-ca setting and also want to configure an Email host:

.. literalinclude:: /include/extend/docker-settings.yaml
   :caption: 10-app-settings.yaml
   :language: yaml

This file can then be added to your image with:

.. code-block:: Dockerfile

   FROM mathiasertl/django-ca
   ADD 10-app-settings.yaml /usr/src/django-ca/ca/conf/

To verify that your settings are included correctly, build the image and print out settings:

.. code-block:: console

    $ docker build -t example .
    $ docker run --rm -it -e DJANGO_CA_SECRET_KEY=dummy example manage shell
    >>> from django.conf import settings
    >>> print(settings.SETTINGS_FILES)
    (PosixPath('/usr/src/django-ca/ca/conf/00-docker.yaml'),)
    >>> print(settings.CA_ENABLE_REST_API)
    True

Extend ``INSTALLED_APPS`` and URL patterns
==========================================

You can extend `INSTALLED_APPS <https://docs.djangoproject.com/en/dev/ref/settings/#installed-apps>`_ as well
as the URL patterns using :ref:`settings-extend-installed-apps` and :ref:`settings-extend-url-patterns`.

***********************
Add NGINX configuration
***********************

If your setup (potentially) uses Compose and adds additional URL endpoints, you will have to add to the NGINX
site configuration provided by the django-ca Docker image. To increase security, the NGINX configuration only
routes known URL endpoints to the application server (Gunicorn).

The NGINX setup usually consists of HTTP and HTTPS configuration. To automatically route HTTP requests to the
application server for HTTP only, add them to ``/usr/src/django-ca/nginx/include.d/http/``. For HTTPS, add
them to ``/usr/src/django-ca/nginx/include.d/https/``. In either case, the files need to have the ``.conf``
file suffix:

.. code-block::
   :caption: :file:`/usr/src/django-ca/nginx/include.d/https/app.conf`

   location /cmc/ {
       try_files "" @django_ca;
   }

You can include any configuration valid in a ``server`` context.

***************************
Use custom image in Compose
***************************

To use a custom image in the standard Compose setup included in **django-ca**, set ``DJANGO_CA_IMAGE`` and
``DJANGO_CA_VERSION`` in your :file:`.env.` file, which gives you full control over the image that will be
loaded:

.. code-block:: bash
   :caption: :file:`.env`

   DJANGO_CA_IMAGE=example
   DJANGO_CA_VERSION=latest

The image will be loaded in the exact same context (Redis, PostgreSQL, ...) as the default image.
