############
Installation
############

You can run **django-ca** as a regular app in any existing Django project of yours, but if you don't have any
Django project running, you can run it as a `standalone project <#as-standalone-project>`_.

Another easy way of running **django-ca** is as a :doc:`Docker container </docker>`.

************
Requirements
************

* Python 3.6+
* Django 2.2 or later
* Any database supported by Django (sqlite3/MySQL/PostgreSQL/...)
* Python, OpenSSL and libffi development headers

If you're using an older system, you can consult this table to see what versions of Python, Django and
cryptography where tested with what release (changes to previous versions in **bold**):

=========== ================= ==================== ================== ============== ============= ===========
django-ca   Python            Django               cryptography       idna           Celery        acme
=========== ================= ==================== ================== ============== ============= ===========
1.19        3.6 - **3.10**    **2.2, 3.1, 3.2**    **3.3** - **35.0** 2.10 - **3.2** 5.0 - **5.1** 1.20
1.18        3.6 - 3.9         **2.2, 3.1, 3.2**    **3.0** - **3.4**  **2.10**       **5.0**
1.17        **3.6** - **3.9** **2.2** - **3.1**    **2.8** - **3.3**  **2.9** - 2.10 **4.3** - 4.4
1.16        3.5 - 3.8         **2.2** - **3.1**    2.7 - **3.0**      2.8 - **2.10** **4.2** - 4.4
1.15        **3.5** - 3.8     1.11, 2.1 - **3.0**  **2.7** - 2.8      2.8            4.0 - 4.4
1.14        2.7/3.5 - **3.8** 1.11, 2.1 - 2.2      **2.5** - **2.8**  **2.8**
=========== ================= ==================== ================== ============== ============= ===========

Note that we don't deliberately break support for older versions, we merely stop testing it. You can try your
luck with older versions.

******************
Use docker-compose
******************

The fastest and by far easiest way to run django-ca with :ref:`docker-compose <docker-compose>`.

The docker-compose file includes everything you need for a sophisticated setup: a PostgreSQL database, an
NGINX web server, a uWSGI application server a distributed Redis cache and a Celery task worker.

***********************************************
As Django app (in your existing Django project)
***********************************************

This chapter assumes that you have an already running Django project and know how to use it.

You need various development headers for pyOpenSSL, on Debian/Ubuntu systems, simply install these packages:

.. code-block:: console

   $ apt-get install gcc python3-dev libffi-dev libssl-dev

You can install **django-ca** simply via pip:

.. code-block:: console

   $ pip install django-ca

and add it to your ``INSTALLED_APPS`` (and if you don't use it already, ``django_object_actions``)::

   INSTALLED_APPS = [
      # ... your other apps...

      'django_object_actions',
      'django_ca',
   ]

... and configure the :doc:`other available settings <settings>` to your liking, then simply run:

.. code-block:: console

   $ python manage.py migrate
   $ python manage.py collectstatic

   # FINALLY, create the root certificates for your CA:
   #     (replace parameters after init_ca with your local details)
   $ python manage.py init_ca RootCA \
   >     /C=AT/ST=Vienna/L=Vienna/O=Org/OU=OrgUnit/CN=ca.example.com

After that, **django-ca** should show up in your admin interface (see :doc:`web_interface`) and provide
various :command:`manage.py` commands (see :doc:`/cli/intro`).

.. _as-standalone:

*********************
As standalone project
*********************

You can also install **django-ca** as a stand-alone project, if you install it via git. The project provides a
:doc:`command-line interface </cli/intro>` that provides complete functionality. The :doc:`web interface
<web_interface>` is optional.

.. NOTE::

   If you don't want the private keys of your CAs on the same machine as the web interface, you can also host
   the web interface on a second server that accesses the same database (CA private keys are hosted on the
   file system, not in the database). You obviously will not be able to sign certificates using the web
   interface, but you can still e.g. revoke certificates or run a :doc:`OCSP responder <ocsp>`.

In the following code-snippet, you'll do all necessary steps to get a basic setup:

.. code-block:: console

   # install dependencies (adapt to your distro):
   $ apt-get install gcc git python3-dev libffi-dev libssl-dev virtualenv

   # clone git repository:
   $ git clone https://github.com/mathiasertl/django-ca.git

   # create virtualenv:
   $ cd django-ca
   $ virtualenv -p /usr/bin/python3 .
   $ source bin/activate

   # install Python dependencies:
   $ pip install -U pip setuptools
   $ pip install -r requirements.txt

In the above script, you have created a `virtualenv
<http://docs.python-guide.org/en/latest/dev/virtualenvs/>`_, meaning that all libraries you install with
:command:`pip install` are installed in the virtualenv (and don't pollute your system). It also means that
before you execute any :command:`manage.py` commands, you'll have to activate your virtualenv, by doing, in
the directory of the git checkout:

.. code-block:: console

   $ source bin/activate

Configure django-ca
===================

.. versionchanged:: 1.15.0

   Until 1.14.0, django-ca imported from a file called ``localsettings.py``. This functionality is deprecated
   and will be removed in ``django-ca>=1.18``.

Before you continue, you have to configure **django-ca**. Django uses a file called ``settings.py``, but so
you don't have to change any files managed by git, it will load a file called ``settings.yaml`` in the same
location so you can override any default settings.  If you deploy using Docker, files are also read from
``/usr/src/django-ca/ca/conf/`` (in alphabetical order).

The `conf/ directory <https://github.com/mathiasertl/django-ca/tree/master/conf>`__ in git includes a few
examples. If you just want to get started, save (and adapt) this file to ``ca/ca/settings.yaml``:

.. code-block:: yaml
   :caption: ca/ca/settings.yaml

   # settings reference:
   #  https://docs.djangoproject.com/en/dev/ref/settings/
   #  https://django-ca.readthedocs.io/en/latest/settings.html

   DEBUG: False

   # WARNING: set this to a long random value:
   SECRET_KEY: secret123

   # Of course, SQLite is not very suitable for production
   DATABASES:
       default:
           ENGINE: django.db.backends.sqlite3
           NAME: db.sqlite3

   # Assumes your CA runs on localhost
   CA_DEFAULT_HOSTNAME: localhost


Initialize the project
======================

After you have configured **django-ca**, you need to initialize the project by running a few
:command:`manage.py` commands:

.. code-block:: console

   $ python ca/manage.py migrate

   # If you intend to run the webinterface (requires STATIC_ROOT setting!)
   $ python ca/manage.py collectstatic

   # FINALLY, create a certificate authority:
   #     (replace parameters after init_ca with your local details)
   $ python manage.py init_ca RootCA /C=AT/ST=Vienna/L=Vienna/O=Org/CN=ca.example.com

Please also see :doc:`/cli/cas` for further information on how to create certificate authorities. You can also
run ``init_ca`` with the ``-h`` parameter for available arguments.

.. _manage_py_shortcut:

Create ``manage.py`` shortcut
=============================

If you don't want to always change the directory to the git checkout, activate the virtualenv and only then
run :command:`manage.py`, you might want to create a shortcut shell script somewhere in your ``PATH`` (e.g.
``/usr/local/bin``):

.. code-block:: bash

   #!/bin/bash

   # BASEDIR is the location of your git checkout
   BASEDIR=/usr/local/share/ca
   PYTHON=${BASEDIR}/bin/python
   MANAGE=${BASEDIR}/ca/manage.py

   ${PYTHON} ${MANAGE} "$@"

Setup a web server
==================

Setting up a web server and all that comes with it is really out of scope of this document. The WSGI file is
located in ``ca/ca/wsgi.py``. Django itself provides some info for using `Apache and mod_wsgi
<ttps://docs.djangoproject.com/en/dev/topics/install/#install-apache-and-mod-wsgi>`_, or you could use `uWSGI
and nginx <http://uwsgi-docs.readthedocs.org/en/latest/tutorials/Django_and_nginx.html>`_, or any of the many
other options available.

GitHub user `Raoul Thill <https://github.com/rthill>`_ notes that you need some special configuration variable
if you use Apache together with ``mod_wsgi`` (see `here
<https://github.com/mathiasertl/django-ca/issues/12#issuecomment-247282915>`_)::

        WSGIDaemonProcess django_ca processes=1 threads=5 \
         python-path=/opt/django-ca/ca:/opt/django-ca/ca/ca:/opt/django-ca/lib/python2.7/site-packages
        WSGIProcessGroup django_ca
        WSGIApplicationGroup %{GLOBAL}
        WSGIScriptAlias / /opt/django-ca/ca/ca/wsgi.py

***************
Configure cache
***************

It's recommended you set up a faster in-memory cache, which will be used e.g. to cache CRLs. In general, the
`CACHES <https://docs.djangoproject.com/en/3.0/ref/settings/#std:setting-CACHES>`__ setting configures the
cache.

If you want to use Redis as a cache, you can install `django-redis-cache
<https://django-redis-cache.readthedocs.io/en/latest/index.html>`__. If you run django-ca as a standalone
project, install django-ca with the ``redis`` extra, otherwise manually install dependencies using pip:

.. code-block:: console

   $ pip install django-ca[redis]  # install redis extra or...
   $ pip install redis hiredis django-redis-cache  # or install deps manually

Configuration for a Redis cache would e.g. look like this:

.. code-block:: yaml
   :caption: settings.yaml

   CACHES:
       default:
           BACKEND: redis_cache.RedisCache
           LOCATION: redis://127.0.0.1:6379
           OPTIONS:
               DB: 1
               PARSER_CLASS: redis.connection.HiredisParser

***********************
Configure Celery worker
***********************

django-ca also supports the `Celery distributed task queue <http://www.celeryproject.org/>`_.

This is especially useful if you want to have e.g. the private keys for a CA on one server and the web
interface including CRLs and OCSP on a separate server: Celery tasks can run on regular intervals to generate
OCSP keys and CRLs on one server and store them to a distributed cache or to a distributed storage system such
as NFS, where they are then accessed by the other server.

Simply install celery with the required broker configuration (see the excellent Celery homepage):

.. code-block:: console

   $ pip install celery[redis]

And add a bit configuration:

.. code-block:: yaml
   :caption: settings.yaml

   CELERY_BROKER_URL: redis://127.0.0.1:6379/0
   CELERY_BEAT_SCHEDULE:
       cache-crls:
           task: django_ca.tasks.cache_crls
           schedule: 86100
       generate-ocsp-keys:
           # schedule is three days minus five minutes, since keys expire after
           # three days by default.
           task: django_ca.tasks.generate_ocsp_keys
           schedule: 258900

Note that the above Celery Beat schedule replaces the cron jobs below.

Now all you have to do is to run Celery:

.. code-block:: console

   $ celery worker -A ca -B -s /var/lib/django-ca/celerybeat-schedule

*****************
Regular cron jobs
*****************

Some :command:`manage.py` commands are intended to be run as cron jobs::

   # assuming you cloned the repo at /root/:
   HOME=/root/django-ca
   PATH=/root/django-ca/bin

   # m h  dom mon dow      user  command

   # Notify watchers about certificates about to expire
   * 8    * * *            root  python ca/manage.py notify_expiring_certs

   # Create CRLs OCSP responder keys
   12 1       * * *           root  python ca/manage.py regenerate_ocsp_keys
   14 0,12    * * *           root  python ca/manage.py cache_crls
