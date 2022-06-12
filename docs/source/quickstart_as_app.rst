########################
Quickstart as Django app
########################

This guide provides instructions for running your own certificate authority as a Django app in your existing
Django project. This setup allows you to integrate django-ca into an existing Django deployment.

In this guide we do not cover creating your own Django project, deployment strategies or regular Python or
Django development.

.. jinja:: requirements-as-py
   :file: include/guide-requirements.rst.jinja
   :header_update_levels:

Required software
=================

You do not need any special software besides Python |minimum-python| or later and a recent version of pip.

It is strongly recommended that you run a `Celery task queue <https://docs.celeryproject.org/>`_. If you do,
you need a message transport like RabbitMQ or Redis. Redis is used in the examples below, because it is
easiest to set up and doubles as a cache.

Python libraries
----------------

If you're using an older system, the table blow lists what versions of Python, Django and cryptography where
tested with what release (changes to previous versions in **bold**):

=========== ============== ================== =============== ============== ============= ===================
django-ca   Python         Django             cryptography    idna           Celery        acme
=========== ============== ================== =============== ============== ============= ===================
1.21        3.7 - 3.10     **3.2** - 4.0      **35.0** - 36.0 **n/a**        5.0 - 5.2     **1.23** - **1.25**
1.20        **3.7 - 3.10** **2.2, 3.2 - 4.0** **3.4 - 36.0**  **3.2, 3.3**   5.0 - **5.2** **1.22**
1.19        3.6 - **3.10** 2.2, 3.1, 3.2      **3.3 - 35.0**  2.10 - **3.2** 5.0 - **5.1** 1.20
1.18        3.6 - 3.9      **2.2, 3.1, 3.2**  **3.0 - 3.4**   **2.10**       **5.0**
1.17        **3.6 - 3.9**  2.2 - 3.1          **2.8 - 3.3**   **2.9** - 2.10 **4.3** - 4.4
1.16        3.5 - 3.8      **2.2** - **3.1**  2.7 - **3.0**   2.8 - **2.10** **4.2** - 4.4
=========== ============== ================== =============== ============== ============= ===================

Note that we don't deliberately break support for older versions, we merely stop testing it. You can try your
luck with older versions.

Starting with ``django-ca==1.21.0``, we no longer test individual versions of ``idna``.

************
Installation
************

For a minimal installation, you can install django-ca via pip:

.. code-block:: console

   user@host:~$ pip install django-ca

There are several extras available, ``acme`` and ``celery`` are strongly recommended:

.. include:: /include/pip-extras.rst

To install django-ca with one or more extras, use the regular pip syntax:

.. code-block:: console

   user@host:~$ pip install django-ca[acme,celery,redis]

*********************
Initial configuration
*********************

Simply add ``django_ca`` to your ``INSTALLED_APPS`` (and if you don't use it already,
``django_object_actions``), as well as a few other required settings::

   INSTALLED_APPS = [
      # ... your other apps...

      'django_object_actions',
      'django_ca',
   ]

   # The hostname used by default for URLs in certificates. Your Django project should be available under this
   # URL using HTTP (see below). If you use ACMEv2, you will also need HTTPS.
   CA_DEFAULT_HOSTNAME = "ca.example.com"

   # RECOMMENDED: Use Celery as an asynchronous task worker if configured
   CELERY_BROKER_URL = "redis://127.0.0.1:6379/0"

   # Enable ACMEv2 support (enabled by default starting 1.22.0). Set to False to completely disable ACMEv2
   # support.
   CA_ENABLE_ACME = True

Please check out :doc:`/settings` for settings specific to django-ca.

You also need to include the URLs in your main file:`urls.py`::

   urlpatterns = [
      path("ca/", include("django_ca.urls")),
      ...
   ]

Finally, invoke the regular :command:`manage.py` commands when you add new apps:

.. code-block:: console

   user@host:~$ python manage.py migrate
   user@host:~$ python manage.py collectstatic

After that, **django-ca** should show up in your admin interface (see :doc:`web_interface`) and provide
various :command:`manage.py` commands (see :doc:`/cli/intro`).

Create admin user and set up CAs
================================

All functionality is available as custom `Djangos manage.py
commands <https://docs.djangoproject.com/en/dev/ref/django-admin/>`_.

.. jinja:: manage-as-py
   :file: include/create-user.rst.jinja

.. jinja:: guide-as-app-where-to-go
   :file: include/guide-where-to-go.rst.jinja
   :header_update_levels:

******
Update
******

.. include:: include/update_intro.rst

You can update django-ca like any other Django app:

.. code-block:: console

   user@host:~$ pip install -U django-ca
   user@host:~$ python manage.py migrate
   user@host:~$ python manage.py collectstatic
