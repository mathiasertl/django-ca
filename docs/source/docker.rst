######################
Quickstart with Docker
######################

This guide provides instructions for running your own certificate authority using a plain Docker container.
Using this setup allows you to run django-ca in an isolated environment that can be easily updated, but use
external resources for a web server, database and cache.

Another use case for this guide is to integrate the image into a Docker Swarm or Kubernetes setup and use the
instructions here as a template.

.. NOTE::

   If you just want to get a CA up and running quickly, why not try :doc:`quickstart_docker_compose`?

This tutorial will give you a CA with

* A root and intermediate CA.
* A browsable admin interface (using plain http)
* Certificate revocation using CRLs and OCSP.
* (Optional) ACMEv2 support (= get certificates using certbot).

TLS support for the admin interface is just a standard TLS setup for NGINX, so this setup is left as an
exercise to the reader.

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
   almost identical to just using :doc:`docker-compose <quickstart_docker_compose>`. If you do not already
   have all the software already set up or want to integrate django-ca into an unsupported orchestration setup
   like Docker Swarm or Kubernetes, you probably really want to just use docker-compose!

On Debian/Ubuntu, simply do:

.. code-block:: console

   user@host:~$ sudo apt update
   user@host:~$ sudo apt install docker.io

.. include:: include/docker-regular-user.rst

.. _docker-configuration:

*********************
Initial configuration
*********************

django-ca requires some initial configuration (like where to find the PostgreSQL server) to run and the domain
name you have set up above.

To provide initial configuration (and any later configuration), create a file called ``localsettings.yaml``
and add at least these settings (and adjust to your configuration):

.. template-include:: yaml include/quickstart_with_docker/localsettings.yaml.jinja
   :caption: localsettings.yaml
   :context: quickstart-with-docker

Note that you can pass simple configuration variables also via environment variables prefixed with
``DJANGO_CA_``. For example, you could also configure the broker URL with:

.. code-block:: console

   user@host:~$ docker run -e DJANGO_CA_CELERY_BROKER_URL=... ...


NGINX configuration
===================

NGINX requires a configuration file, so you first need to create it. A minimal example would be:

.. template-include:: nginx include/quickstart_with_docker/nginx.conf.jinja
   :caption: nginx.conf
   :context: quickstart-with-docker

Recap
=====

By now, there should be two configuration files in your local directory: ``localsettings.yaml`` configures
django-ca, and ``nginx.conf`` configures NGINX itself:

.. code-block:: bash

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
   :include: include/quickstart_with_docker/start-dependencies.yaml
   :context: quickstart-with-docker

Start django-ca
===============

django-ca (usually) consists of two containers (using the same image): A uWSGI server and a Celery task queue.
You thus need to start two containers with slightly different configuration:

.. console-include::
   :include: include/quickstart_with_docker/start-django-ca.yaml
   :context: quickstart-with-docker


Start NGINX
===========

NGINX unfortunately will crash if you haven't started django-ca first (due to the name of the frontend
container not resolving yet). So you have to start NGINX *after* the frontend container:

.. code-block:: console

   user@host:~$ docker run --name nginx -p 80:80 --network=django-ca \
   >     -v static:/usr/share/nginx/html/static/ \
   >     -v `pwd`/nginx.conf:/etc/nginx/conf.d/default.conf -d nginx

Create admin user and set up CAs
================================

It's finally time to create a user for the admin interface and some certificate authorities.

.. code-block:: console

   user@host:~$ docker exec -it backend manage createsuperuser
   user@host:~$ docker exec -it backend manage init_ca --pathlen=1 Root "/CN=Root CA"
   user@host:~$ docker exec -it backend manage init_ca \
   >     --path=ca/shared/ --parent="Root CA" Intermediate "/CN=Intermediate CA"

***********
Use your CA
***********

Please see :ref:`docker-compose-use-ca` for further usage information.

************************
Build your own container
************************

If you want to build the container by yourself, simply clone `the repository from GitHub
<https://github.com/mathiasertl/django-ca/>`_ and execute::

   DOCKER_BUILDKIT=1 docker build -t django-ca .

******
Update
******

.. include:: include/update_intro.rst

Docker does not support updating containers very well on its own. Upgrading them means stopping and removing
the old container and starting a new one with the same options:

.. code-block:: console

   user@host:~$ docker ps
   CONTAINER ID   IMAGE                          ...	NAMES
   ...            mathiasertl/django-ca:1.19.0   ...	frontend
   ...            mathiasertl/django-ca:1.19.0   ...	backend
   user@host:~$ docker kill frontend backend
   user@host:~$ docker rm frontend backend
   user@host:~$ docker run ... mathiasertl/django-ca:1.20.0 frontend
   user@host:~$ docker run ... mathiasertl/django-ca:1.20.0 backend

The ``docker run`` command must use at least the same volume options as the previous command.
