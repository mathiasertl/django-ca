######################
Quickstart with Docker
######################

.. spelling:word-list::

   mathiasertl
   ghcr
   io

.. structured-tutorial:: docker/tutorial.yaml

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

.. include:: /include/guide-requirements.rst

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

.. structured-tutorial-part:: install-dependencies

.. structured-tutorial-part:: add-docker-group

.. _docker-configuration:

*********************
Initial configuration
*********************

django-ca requires some initial configuration (like where to find the PostgreSQL server) to run and the domain
name you have set up above.

Django requires a ``SECRET_KEY`` to run, and it should be shared between the Celery worker and the Gunicorn
instance. Generate a sufficiently long secret key and set it as ``SECRET_KEY`` below:

.. structured-tutorial-part:: generate-secret-key

To provide initial configuration (and any later configuration), create a file called ``localsettings.yaml``
and add at least these settings (and adjust to your configuration):

.. structured-tutorial-part:: create-localsettings.yaml

Please see :doc:`/settings` for a list of available settings and especially :ref:`settings-yaml-configuration`
for more YAML configuration examples.

Note that you can pass simple configuration variables also via environment variables prefixed with
``DJANGO_CA_``. For example, you could also configure the broker URL with:

.. code-block:: console

   user@host:~$ docker run -e DJANGO_CA_CELERY_BROKER_URL=... ...


NGINX configuration
===================

NGINX requires a configuration file, so you first need to create it. A minimal example would be:

.. structured-tutorial-part:: create-nginx.conf

Recap
=====

By now, there should be two configuration files in your local directory: ``localsettings.yaml`` configures
django-ca, and ``nginx.conf`` configures NGINX itself:

.. structured-tutorial-part:: recap-test-files

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

.. structured-tutorial-part:: start-dependencies

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

.. structured-tutorial-part:: verify-attestations

Start django-ca
===============

django-ca (usually) consists of three containers (using the same image):

#. A `celery beat <https://docs.celeryq.dev/en/latest/userguide/periodic-tasks.html>`_ daemon for periodic
   tasks.
#. A Celery worker to handle asynchronous tasks
#. A `Gunicorn <https://gunicorn.org/>`_-based WSGI server for HTTP endpoints

You thus need to start three containers with slightly different configuration:

.. structured-tutorial-part:: start-django-ca


You can also use different versions of the Docker image, including images based on Alpine Linux. Please see
the `Docker Hub page <https://hub.docker.com/r/mathiasertl/django-ca>`_ for more information about available
tags.

Start NGINX
===========

NGINX unfortunately will crash if you haven't started django-ca first (due to the name of the frontend
container not resolving yet). So you have to start NGINX *after* the frontend container:

.. structured-tutorial-part:: start-nginx

You are now able to view the admin interface at http://ca.example.com/admin/. You cannot log in yet, as you
haven't created a user yet.

Verify setup
============

.. structured-tutorial-part:: verify-containers

You can also run the deployment checks for your setup:

.. structured-tutorial-part:: deployment-checks

Create admin user and set up CAs
================================

It's finally time to create a user for the admin interface and some certificate authorities.

.. structured-tutorial-part:: create-user-and-ca

***********
Use your CA
***********

Usage is very similar to the :ref:`usage in Docker Compose <docker-compose-use-ca>`, for example to sign a
certificate:

.. structured-tutorial-part:: sign-cert

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
