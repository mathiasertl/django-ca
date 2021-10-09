##############################
Quickstart with docker-compose
##############################

This guide is supposed to give you a quick start for running your own CA using docker-compose. It does not
give to many details about how to configure more stuff, please read the other documentation in more detail to
get more information.

This tutorial assumes you have moderate knowledge of running servers, installing software, docker,
docker-compose and how TLS certificates work.

This tutorial will give you a CA with

* A root and intermediate CA.
* An browsable admin interface, protected by TLS (using Let's Encrypt certificates).
* Certificate revocation using CRLs and OCSP.
* (Optional) ACMEv2 support (= get certificates using certbot).

************
Requirements
************

We assume you have a dedicated server that can run your CA, and a suitable DNS name that points to that
server. The server needs to run Docker with docker-compose.

The default setup binds to the privileged ports 80 and 443, so it is assumed that no other web server runs on
your server (or anything else listening on that port).

*********
Setup DNS
*********

First, decide on the hostname you want to use. Since this information is encoded in CA certificates, the
hostname cannot be easily changed later.

For the purposes of this tutorial, we are going to assume that ``ca.example.com`` is a DNS entry that points
to the server where you want to set up your certificate authority.

*************************
Install required software
*************************

To run **django-ca**, you need Docker and Docker Compose. You also need certbot to acquire Let's Encrypt
certificates for the admin interface. OpenSSL is used to generate the DH parameter file. On Debian/Ubuntu,
simply do:

.. code-block:: console

   user@host:~$ sudo apt update
   user@host:~$ sudo apt install docker.io docker-compose certbot openssl

For a different OS, please read `Install Docker <https://docs.docker.com/engine/install/>`_, `Install
docker-compose <https://docs.docker.com/compose/install/>`_ and `Get certbot
<https://certbot.eff.org/docs/install.html>`_.

If you want to run docker(-compose) as a regular user, you need to add your user to the ``docker`` group and
log in again:

.. code-block:: console

   user@host:~$ sudo adduser `id -un` docker

************************
Get initial certificates
************************

Use certbot to acquire initial certificates. This must be done `before` you run docker-compose, as both bind
to port 80 (HTTP).

.. code-block:: console

   user@host:~$ sudo certbot certonly --standalone -d ca.example.com
   ...
   user@host:~$ sudo ls /etc/letsencrypt/live/ca.example.com
   README  cert.pem  chain.pem  fullchain.pem  privkey.pem

.. _docker-compose.yml:

*****************
Get configuration
*****************

Docker-compose needs a configuration file, :download:`docker-compose.yml </_files/docker-compose.yml>`. You
can also download the file for other versions `from github
<https://github.com/mathiasertl/django-ca/blob/master/docker-compose.yml>`_.

.. NOTE::

   Because of how docker-compose works, it is better to put the file in a sub-directory and `not` directly into
   your home directory. We assume you put all files into ``~/ca/`` from now on.

You can also get versions for specific versions of **django-ca** from the table below, which also shows
bundled third-party Docker images.

====================================================== ===== =========== =====
Version                                                Redis PostgreSQL  NGINX
====================================================== ===== =========== =====
:download:`1.18.0 </_files/1.18.0/docker-compose.yml>` 6     12          1.18
:download:`1.17.3 </_files/1.17.3/docker-compose.yml>` 6     12          1.18
:download:`1.16.0 </_files/1.16.0/docker-compose.yml>` 6     12          1.18
====================================================== ===== =========== =====

Add ``docker-compose.override.yml``
===================================

The default :file:`docker-compose.yml` does not offer HTTPS, because to many details (cert location, etc.) are
different from system to system. We need to add a `docker-compose override file
<https://docs.docker.com/compose/extends/>`_ to open the port and map the directories with the certificates
into the container.  Simply add a file called :file:`docker-compose.override.yml` next to your main
configuration file:

.. code-block:: yaml
   :caption: docker-compose.override.yml

   version: "3.6"
   services:
       webserver:
           volumes:
               - /etc/letsencrypt/live/${DJANGO_CA_CA_DEFAULT_HOSTNAME}:/etc/certs/live/${DJANGO_CA_CA_DEFAULT_HOSTNAME}/
               - /etc/letsencrypt/archive/${DJANGO_CA_CA_DEFAULT_HOSTNAME}:/etc/certs/archive/${DJANGO_CA_CA_DEFAULT_HOSTNAME}/
               - ${PWD}/dhparam.pem:/etc/nginx/dhparams/dhparam.pem
               - ${PWD}/acme/:/usr/share/django-ca/acme/
           ports:
               - 443:443

This will work if you get your certificates using ``certbot`` or a similar client. If your private key in
public key chain is named different, you can set ``NGINX_PRIVATE_KEY`` and ``NGINX_PUBLIC_KEY`` in your
:file:`.env` file below.

Add ``.env`` file
=================

Some settings in **django-ca** can be configured with environment variables (except where a more complex
structure is required). Simply create a file called :file:`.env` next to :file:`docker-compose.yaml`.

For a quick start, there are only a few variables you need to specify:

.. code-block:: bash

   # The hostname for your CA.
   # WARNING: Changing this requires new CAs (because the hostname goes into the certificates).
   DJANGO_CA_CA_DEFAULT_HOSTNAME=ca.example.com

   # If you want to enable *experimental* ACMEv2 support:
   #DJANGO_CA_CA_ENABLE_ACME=true

   # PostgreSQL superuser password (required by the Docker image), see also:
   #   https://hub.docker.com/_/postgres
   #
   # Generate a secure password e.g. with "openssl rand -base64 32"
   POSTGRES_PASSWORD=mysecretpassword

   # NGINX TLS configuration
   NGINX_TEMPLATE=tls
   NGINX_PRIVATE_KEY=/etc/certs/live/ca.example.com/privkey.pem
   NGINX_PUBLIC_KEY=/etc/certs/live/ca.example.com/fullchain.pem

Generate DH parameters
======================

The TLS configuration also requires that you generate a DH parameter file, used by some TLS ciphers. You can
generate it with:

.. code-block:: console

   user@host:~/ca/$ openssl dhparam -dsaparam -out dhparam.pem 4096

Recap
=====

By now, you should have four files in ``~/ca/``:

.. code-block:: console

   user@host:~/ca/$ ls -A
   docker-compose.yml docker-compose.override.yml .env dhparam.pem

*************
Start your CA
*************

Now, you can start **django-ca** for the first time. Inside the folder with all your configuration, run
docker-compose (and verify that everything is running):

.. code-block:: console

   user@host:~/ca/$ docker-compose up -d
   ...
   Creating django-ca_backend_1  ... done
   Creating django-ca_webserver_1 ... done
   user@host:~/ca/$ docker-compose ps
   Name                       Command               State         Ports
   -----------------------------------------------------------------------------------
   django-ca_backend_1     ./celery.sh -l info              Up
   django-ca_cache_1       docker-entrypoint.sh redis ...   Up
   django-ca_db_1          docker-entrypoint.sh postgres    Up
   django-ca_frontend_1    /bin/sh -c ./uwsgi.sh            Up
   django-ca_webserver_1   /docker-entrypoint.sh /bin ...   Up    0.0.0.0:443->443/tcp,...

By now, you should be able to see the admin interface (but not log in yet - you haven't created a user yet).
Simply go to https://ca.example.com/admin/.

Create admin user and set up CAs
================================

Inside the backend container, ``manage`` is an alias for the `Djangos manage.py script
<https://docs.djangoproject.com/en/dev/ref/django-admin/>`_. We provide many custom management commands, see
:doc:`/cli/intro`. We need to create a user (that can log into the admin interface) and create a root and
intermediate CA:

.. code-block:: console

   user@host:~/ca/$ docker-compose exec backend manage createsuperuser
   ...
   user@host:~/ca/$ docker-compose exec backend manage init_ca \
   >     --pathlen=1 Root "/CN=Root CA"
   user@host:~/ca/$ docker-compose exec backend manage init_ca \
   >     --path=ca/shared/ --parent="Root CA" Intermediate "/CN=Intermediate CA"

There are a few things to break down in the above commands:

* The subject (``/CN=...``) in the CA is only used by browsers to display the name of a CA. It can be any
  human readable value and does not have to be a domain name.
* The first positional argument to ``init_ca``, ("Root", "Intermediate") is just a human readable name used to
  identify the CA within the command-line interface and web interface. Unlike the CommonName, it must be
  unique.
* The ``--path=ca/shared/`` parameter for the intermediate CA means that you can use the admin interface to
  issue certificates. Without it, the web server has no access to the private key for your CA.
* The ``--pathlen=1`` parameter for the root CA means that there is at most one level of intermediate CAs.

***********
Use your CA
***********

You now should be able to log into the admin interface you set up at https://ca.example.com/admin/ with the
credentials you created above. In the admin interface, you can create certificates for the "Intermediate" CA
but not for the "Root" CA (since you didn't pass ``--path=ca/shared/``). You can also use the admin interface
to revoke any certificate.

You can always use the :doc:`/cli/intro` for advanced administration operations, including creating
certificates for any CA and revoking certificates.

CRL and OCSP services are provided by default, there's nothing you need to do to enable them.

Use ACME with certbot
======================

If you enabled :doc:`ACMEv2 support <acme>`, all you need to do is enable ACMEv2 for the intermediate CA using
the admin interface (or using ``manage edit_ca``). After that, you can retrieve a certificate using a simple
certbot command:

.. code-block:: console

   $ sudo certbot register --server https://ca.example.com/django_ca/acme/directory/
   $ sudo certbot certonly --server https://ca.example.com/django_ca/acme/directory/ ...
