########################
Quickstart as Django app
########################

This guide provides instructions for running your own certificate authority as a Django app in your existing
Django project. This setup allows you to integrate django-ca into an existing Django deployment.

In this guide we do not cover creating your own Django project, deployment strategies or regular Python or
Django development.

************
Requirements
************

.. jinja:: requirements-as-py
   :file: include/guide-requirements.rst.jinja
   :header_update_levels:

Required software
=================

You do not need any special software besides Python |minimum-python| or later and a recent version of pip.

If you want to use ACMEv2 or Celery, you need a cache that shares data between individual processes. From the
backends included in Django, Memcached and Redis do this. This document configures Redis as a cache.

It is strongly recommended that you run a `Celery task queue <https://docs.celeryproject.org/>`_. If you do,
you need a message transport like RabbitMQ or Redis. Redis is used in the examples below, because it is
easiest to set up and doubles as a cache.

Python libraries
----------------

If you're using an older system, the table blow lists what versions of Python, Django and cryptography where
tested with what release (changes to previous versions in **bold**):

.. Keep no more then 10 releases in this table.

========= =============== ================== =============== ============= ================ ==================
django-ca Python          Django             cryptography    Celery        acme             pydantic
========= =============== ================== =============== ============= ================ ==================
2.3       **3.10** - 3.13 **5.1 - 5.2**      44 - **45**     5.4 - **5.5** **3.2 - 4.1**    **2.10 - 2.11**
2.2       3.9 - 3.13      4.2, 5.1           **44**          5.4           **3.0 - 3.2**    **2.10**
2.1       3.9 - **3.13**  4.2 - 5.1          **43 - 44**     5.4           **2.11 - 3.0**   **2.9 - 2.10**
2.0       3.9 - 3.12      4.2 - **5.1**      42 - **43**     **5.4**       **2.10** - 2.11  **2.7 - 2.9**
1.29      **3.9** - 3.12  4.2 - 5.0          **42**          5.3 - **5.4** **2.9 - 2.11**   2.5 - **2.7**
1.28      3.8 - 3.12      **4.2 - 5.0**      41 - **42**     5.3           **2.7 - 2.9**    2.5 - 2.6
1.27      3.8 - **3.12**  3.2, **4.2**       **41**          **5.3**       2.6 - **2.7**
1.26      3.8 - 3.11      3.2, 4.1 - 4.2     **40** - 41     **5.2** - 5.3 **2.5** - 2.6
1.25      3.8 - 3.11      3.2, 4.1 - 4.2     37, 39 - **41** 5.1 - **5.3** **2.3 - 2.6**
1.24      3.8 - 3.11      3.2, 4.1 - **4.2** 37, 39 - **40** 5.1 - 5.2     **2.2 - 2.5**
========= =============== ================== =============== ============= ================ ==================

Note that we don't deliberately break support for older versions, we merely stop testing it. You can try your
luck with older versions.

************
Installation
************

For a minimal installation, you can install django-ca via pip:

.. code-block:: console

   user@host:~$ pip install django-ca

There are several extras available, the ``celery`` and ``redis`` extras are strongly recommended:

.. include:: /include/pip-extras.rst

To install django-ca with one or more extras, use the regular pip syntax:

.. code-block:: console

   user@host:~$ pip install django-ca[celery,redis]

*********************
Initial configuration
*********************

Simply add ``django_ca`` to your ``INSTALLED_APPS`` (and if you don't use it already,
``django_object_actions``), as well as a few other required settings:

.. literalinclude:: /include/quickstart_as_app/settings.py
   :language: python

Please check out :doc:`/settings` for settings specific to django-ca.

You also need to include the URLs in your main :file:`urls.py`:

.. literalinclude:: /include/quickstart_as_app/urls.py
   :language: python

You can verify (some) aspects of the setup using Django system checks:

.. code-block:: console

   user@host:~$ python manage.py check --deploy

Finally, invoke the regular :command:`manage.py` commands when you add new apps:

.. code-block:: console

   user@host:~$ python manage.py migrate
   user@host:~$ python manage.py collectstatic

After that, **django-ca** should show up in your admin interface (see :doc:`/web_interface`) and provide
various :command:`manage.py` commands (see :doc:`/cli/intro`).

Create admin user and set up CAs
================================

All functionality is available as custom `Django's manage.py
commands <https://docs.djangoproject.com/en/dev/ref/django-admin/>`_.

.. jinja:: manage-as-py
   :file: include/create-user.rst.jinja

.. jinja:: guide-as-app-where-to-go
   :file: include/guide-where-to-go.rst.jinja
   :header_update_levels:

******
Update
******

.. include:: /include/update_intro.rst

You can update django-ca like any other Django app:

.. code-block:: console

   user@host:~$ pip install -U django-ca
   user@host:~$ python manage.py migrate
   user@host:~$ python manage.py collectstatic
