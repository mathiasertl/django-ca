######################
Quickstart with Docker
######################

.. spelling::

   mathiasertl
   ghcr
   io

This guide provides instructions for running your own certificate authority using a plain Docker container.
Using this setup allows you to run django-ca in an isolated environment that can be easily updated, but use
external resources for a web server, database and cache.

Another use case for this guide is to integrate the image into a Docker Swarm or Kubernetes setup and use the
instructions here as a template.

.. NOTE::

   If you just want to get a CA up and running quickly, why not try :doc:`/quickstart/docker_compose`?

This tutorial will give you a CA with

* A root and intermediate CA.
* A browsable admin interface (using plain http)
* Certificate revocation using CRLs and OCSP.
* (Optional) ACMEv2 support (= get certificates using certbot).

TLS support for the admin interface is just a standard TLS setup for NGINX, so this setup is left as an
exercise to the reader.

************
Requirements
************

.. jinja:: requirements-in-docker
   :file: include/guide-requirements.rst.jinja
   :header_update_levels:

Required software
=================

To run **django-ca**, you need Docker. You will also need at least a `supported database
<https://docs.djangoproject.com/en/4.0/ref/databases/>`_ and a web server (like NGINX or Apache) to serve
static files.

In our guide, we are going to run PostgreSQL as a database, Redis as a cache and NGINX as a front-facing web
server each in a separate Docker container. Please refer to your operating system installation instructions
for how to install the software on your own.

.. NOTE::

   Starting dependencies as Docker containers serves us well for this guide, but makes the guide technically
   almost identical to just using :doc:`docker-compose </quickstart/docker_compose>`. If you do not already
   have all the software already set up or want to integrate django-ca into an unsupported orchestration setup
   like Docker Swarm or Kubernetes, you probably really want to just use docker-compose!

On Debian/Ubuntu, simply do:

.. code-block:: console

   user@host:~$ sudo apt update
   user@host:~$ sudo apt install docker.io

.. include:: /include/docker-regular-user.rst

.. _docker-configuration:

*********************
Initial configuration
*********************

django-ca requires some initial configuration (like where to find the PostgreSQL server) to run and the domain
name you have set up above.

Django requires a ``SECRET_KEY`` to run, and it should be shared between the Celery worker and the Gunicorn
instance. Generate a sufficiently long secret key and set it as ``SECRET_KEY`` below:

.. code-block:: console

   user@host:~$ cat /dev/urandom | tr -dc '[:alnum:][:punct:]' | tr -d '"' | fold -w ${1:-50} | head -n 1

To provide initial configuration (and any later configuration), create a file called ``localsettings.yaml``
and add at least these settings (and adjust to your configuration):

.. template-include:: yaml /include/quickstart_with_docker/localsettings.yaml.jinja
   :caption: localsettings.yaml
   :context: quickstart-with-docker

Please see :doc:`/settings` for a list of available settings and especially :ref:`settings-yaml-configuration`
for more YAML configuration examples.

Note that you can pass simple configuration variables also via environment variables prefixed with
``DJANGO_CA_``. For example, you could also configure the broker URL with:

.. code-block:: console

   user@host:~$ docker run -e DJANGO_CA_CELERY_BROKER_URL=... ...


NGINX configuration
===================

NGINX requires a configuration file, so you first need to create it. A minimal example would be:

.. template-include:: nginx /include/quickstart_with_docker/nginx.conf.jinja
   :caption: nginx.conf
   :context: quickstart-with-docker

Recap
=====

By now, there should be two configuration files in your local directory: ``localsettings.yaml`` configures
django-ca, and ``nginx.conf`` configures NGINX itself:

.. code-block:: console

   user@host:~$ ls
   nginx.conf localsettings.yaml

***************
Start django-ca
***************

After configuration, start service dependencies, django-ca itself and finally NGINX, then create an admin user
and some initial certificate authorities.

Start dependencies
==================

As mentioned before, we will start services that django-ca depends upon (like PostgreSQL) as Docker containers
in this guide. In practice, you do not need the custom network setup below, unless you intend to run some of
the services this way.

Create a Docker network and start PostgreSQL and Redis:

.. console-include::
   :include: /include/quickstart_with_docker/start-dependencies.yaml
   :context: quickstart-with-docker

Choose Docker image
===================

The Docker image is published in a Debian (the default) and an Alpine Linux based variant. In the examples
below, we use the default, Debian based variant. For example, if you use |last-version|, you can either
choose:

* mathiasertl/django-ca:|last-version|
* mathiasertl/django-ca:|last-version|-alpine

The above images are updated if packaging issues or security vulnerabilities in dependencies are discovered.
If you want to be sure that you can download the exact same image later, the same tags are also published with
a datestamp suffix, e.g. mathiasertl/django-ca:|last-version|-20251231.

.. versionchanged:: 2.5.0

   Docker images now use a datestamp (e.g. "20251231") as suffix, instead of an increasing integer.

.. versionadded:: 2.3.0

   Docker images are now also published to the GitHub container registry at ``ghcr.io``.

Starting with 2.3.0, GitHubs container registry also stores the same django-ca images:

* ghcr.io/mathiasertl/django-ca:|last-version|
* ghcr.io/mathiasertl/django-ca:|last-version|-20251231
* ghcr.io/mathiasertl/django-ca:|last-version|-alpine
* ghcr.io/mathiasertl/django-ca:|last-version|-alpine-20251231

Verify attestations
-------------------

.. versionadded:: 2.3.0

   Docker image attestations where added. Earlier images do *not* have attestations.

.. console-include::
   :include: /include/quickstart_with_docker/attest-image.yaml
   :context: quickstart-with-docker

Start django-ca
===============

django-ca (usually) consists of three containers (using the same image):

#. A `Gunicorn <https://gunicorn.org/>`_-based WSGI server for HTTP endpoints
#. A Celery worker to handle asynchronous tasks
#. A `celery beat <https://docs.celeryq.dev/en/latest/userguide/periodic-tasks.html>`_ daemon for periodic
   tasks.

You thus need to start three containers with slightly different configuration:

.. console-include::
   :include: /include/quickstart_with_docker/start-django-ca.yaml
   :context: quickstart-with-docker

You can also use different versions of the Docker image, including images based on Alpine Linux. Please see
the `Docker Hub page <https://hub.docker.com/r/mathiasertl/django-ca>`_ for more information about available
tags.

Start NGINX
===========

NGINX unfortunately will crash if you haven't started django-ca first (due to the name of the frontend
container not resolving yet). So you have to start NGINX *after* the frontend container:

.. console-include::
   :include: /include/quickstart_with_docker/start-nginx.yaml
   :context: quickstart-with-docker

You are now able to view the admin interface at http://ca.example.com. You cannot log in yet, as you haven't
created a user yet.

Create admin user and set up CAs
================================

It's finally time to create a user for the admin interface and some certificate authorities.

.. console-include::
   :include: /include/quickstart_with_docker/setup-cas.yaml
   :context: quickstart-with-docker

***********
Use your CA
***********

Please see :ref:`docker-compose-use-ca` for further usage information.

************************
Build your own container
************************

If you want to build the container by yourself, simply clone `the repository from GitHub
<https://github.com/mathiasertl/django-ca/>`_ and execute:

.. code-block:: console

   $ DOCKER_BUILDKIT=1 docker build -t django-ca .

******
Update
******

.. include:: /include/update_intro.rst

Docker does not support updating containers very well on its own. Upgrading them means stopping and removing
the old container and starting a new one with the same options:

.. code-block:: console

   user@host:~$ docker ps
   CONTAINER ID   IMAGE                          ...	NAMES
   ...            mathiasertl/django-ca:1.28.0   ...	frontend
   ...            mathiasertl/django-ca:1.28.0   ...	backend
   user@host:~$ docker kill frontend backend
   user@host:~$ docker rm frontend backend
   user@host:~$ docker run ... mathiasertl/django-ca:1.29.0 frontend
   user@host:~$ docker run ... mathiasertl/django-ca:1.29.0 backend

The ``docker run`` command must use at least the same volume options as the previous command.
