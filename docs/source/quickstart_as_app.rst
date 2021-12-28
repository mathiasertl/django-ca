#########################
Quickstart: as Django app
#########################

This guide provides instructions for running your own certificate authority as a Django app in your existing
Django project. This setup allows you to integrate django-ca into aan existing Django deployment.

In this guide we do not cover creating your own Django project, deployment strategies or regular Python or
Django development.

.. include:: include/guide_requirements.rst

Required software
=================

You do not need any special software besides a recent version of pip.

It is strongly recommended that you run a `Celery task queue <https://docs.celeryproject.org/>`_. If you do,
you need a message transport like RabbitMQ or Redis. Redis is used in the examples below, because it is
easiest to set up and doubles as a cache.

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

   # If you want to enable *experimental* ACMEv2 support:
   #DJANGO_CA_CA_ENABLE_ACME = True

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

HTTP availability?!
===================

It might seem a bit ironic and confusing, but certificate revocation status protocols like OCSP or CRLs
usually works via HTTP, **not** HTTPS. Responses from the CA are always signed, so hosting them via HTTP is not a
security vulnerability. Further, you cannot verify the the certificate used when querying the CA, since you
would need a certificate revocation status for that.

Just in case you doubt the above: check how publicly trusted and widely used certificate authorities set the
:ref:`ca-example-crlDistributionPoints` and :ref:`ca-example-AuthorityInfoAccess` extensions.

However, only CRL, OCSP and issuer information needs to be available via HTTP. If you use ``/ca`` as path in
your URL configuration (like in the example above), you only need ``/ca/issuer/``, ``/ca/ocsp/`` and
``/ca/crl/`` available via HTTP.


Create admin user and set up CAs
================================

All functionality is available as custom `Djangos manage.py
commands <https://docs.djangoproject.com/en/dev/ref/django-admin/>`_.

.. jinja:: manage-as-py
   :file: /source/include/create-user.rst.jinja
