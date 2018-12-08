Installation
============

You can run **django-ca** as a regular app in any existing Django project of
yours, but if you don't have any Django project running, you can run it as a
`standalone project <#as-standalone-project>`_.

Another easy way of running **django-ca** is as a :doc:`Docker container
</docker>`.

Requirements
____________

* Python 2.7 or Python 3.4+
* Django 1.11+
* Any database supported by Django (sqlite3/MySQL/PostgreSQL/...)
* Python, OpenSSL and libffi development headers

If you're using an older system, you can consult this table to see what versions
of Python, Django and cryptography where tested with what release:

=========== ============== ================= ============ =========
django-ca   Python         Django            cryptography idna
=========== ============== ================= ============ =========
1.4         2.7/3.4 - 3.6  1.8 - 1.10        1.7
1.5         2.7/3.4 - 3.6  1.8 - 1.11        1.7
1.6         2.7/3.4 - 3.6  1.8, 1.10 - 1.11  1.8
1.7         2.7/3.4 - 3.6  1.8, 1.10 - 2.0   2.1 - 2.2
1.8         2.7/3.4 - 3.6  1.11 - 2.0        2.1 - 2.2
1.9         2.7/3.4 - 3.6  1.11 - 2.1        2.1 - 2.3
1.10        2.7/3.4 - 3.7  1.11 - 2.1        2.1 - 2.3
1.11        2.7/3.4 - 3.7  1.11 - 2.1        2.1 - 2.4    2.6 - 2.8
=========== ============== ================= ============ =========

As Django app (in your existing Django project)
_______________________________________________

This chapter assumes that you have an already running Django project and know how to use it.

You need various development headers for pyOpenSSL, on Debian/Ubuntu systems, simply install these
packages:

.. code-block:: console

   $ apt-get install gcc python3-dev libffi-dev libssl-dev

You can install **django-ca** simply via pip:

.. code-block:: console

   $ pip install django-ca

and add it to your ``INSTALLED_APPS``::

   INSTALLED_APPS = [
      # ... your other apps...

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

After that, **django-ca** should show up in your admin interface (see :doc:`web_interface`) and
provide various ``manage.py`` commands (see :doc:`/cli/intro`).

.. _as-standalone:

As standalone project
_____________________

You can also install **django-ca** as a stand-alone project, if you install it via git. The project
provides a :doc:`command-line interface </cli/intro>` that provides complete functionality. The
:doc:`web interface <web_interface>` is optional.

.. NOTE::

   If you don't want the private keys of your CAs on the same machine as the web interface, you can
   also host the web interface on a second server that accesses the same database (CA private keys
   are hosted on the filesystem, not in the database). You obviously will not be able to sign
   certificates using the web interface, but you can still e.g. revoke certificates or run a
   :doc:`OCSP responder <ocsp>`.

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
<http://docs.python-guide.org/en/latest/dev/virtualenvs/>`_, meaning that all
libraries you install with ``pip install`` are installed in the virtualenv (and
don't pollute your system). It also means that before you execute any
``manage.py`` commands, you'll have to activate your virtualenv, by doing, in
the directory of the git checkout:

.. code-block:: console

   $ source bin/activate

Configure django-ca
-------------------

Before you continue, you have to configure **django-ca**. Django uses a file called
``settings.py``, but so you don't have to change any files managed by git, it includes
``localsettings.py`` in the same directory. So copy the example file and edit it with your
favourite editor:

.. code-block:: console

   $ cp ca/ca/localsettings.py.example ca/ca/localsettings.py

The most important settings are documented there, but you can of course use any setting `provided
by Django <https://docs.djangoproject.com/en/dev/topics/settings/>`_.

.. WARNING::

   The ``SECRET_KEY`` and ``DATABASES`` settings are absolutely mandatory. If you use the
   :doc:`web_interface`, the ``STATIC_ROOT`` setting is also mandatory.

Initialize the project
----------------------

After you have configured **django-ca**, you need to initialize the project by running a few
``manage.py`` commands:

.. code-block:: console

   $ python ca/manage.py migrate

   # If you intend to run the webinterface (requires STATIC_ROOT setting!)
   $ python ca/manage.py collectstatic

   # FINALLY, create a certificate authority:
   #     (replace parameters after init_ca with your local details)
   $ python manage.py init_ca RootCA /C=AT/ST=Vienna/L=Vienna/O=Org/CN=ca.example.com

Please also see :doc:`/cli/cas` for further information on how to create certificate
authorities. You can also run ``init_ca`` with the ``-h`` parameter for available arguments.

.. _manage_py_shortcut:

Create manage.py shortcut
-------------------------

If you don't want to always chdir to the git checkout, activate the virtualenv
and only then run ``manage.py``, you might want to create a shortcut shell
script somewhere in your ``PATH`` (e.g. ``/usr/local/bin``):

.. code-block:: bash

   #!/bin/bash

   # BASEDIR is the location of your git checkout
   BASEDIR=/usr/local/share/ca
   PYTHON=${BASEDIR}/bin/python
   MANAGE=${BASEDIR}/ca/manage.py

   ${PYTHON} ${MANAGE} "$@"

Setup a webserver
-----------------

Setting up a webserver and all that comes with it is really out of scope of
this document. The WSGI file is located in ``ca/ca/wsgi.py``. Django itself
provides some info for using `Apache and mod_wsgi
<ttps://docs.djangoproject.com/en/dev/topics/install/#install-apache-and-mod-wsgi>`_,
or you could use `uWSGI and nginx
<http://uwsgi-docs.readthedocs.org/en/latest/tutorials/Django_and_nginx.html>`_,
or any of the many other options available.

Apache and mod_wsgi
___________________

Github user `Raoul Thill <https://github.com/rthill>`_ notes that you need some special
configuration variable if you use Apache together with mod_wsgi (see `here
<https://github.com/mathiasertl/django-ca/issues/12#issuecomment-247282915>`_)::

        WSGIDaemonProcess django_ca processes=1 python-path=/opt/django-ca/ca:/opt/django-ca/ca/ca:/opt/django-ca/lib/python2.7/site-packages threads=5
        WSGIProcessGroup django_ca
        WSGIApplicationGroup %{GLOBAL}
        WSGIScriptAlias / /opt/django-ca/ca/ca/wsgi.py


Regular cronjobs
________________

Some ``manage.py`` commands are intended to be run as cronjobs::

   # assuming you cloned the repo at /root/:
   HOME=/root/django-ca
   PATH=/root/django-ca/bin

   # m h  dom mon dow      user  command

   # notify watchers about certificates about to expire
   * 8    * * *            root  python ca/manage.py notify_expiring_certs

   # recreate the CRL and the OCSP index
   12 *    * * *           root  python ca/manage.py dump_crl
   14 *    * * *           root  python ca/manage.py dump_ocsp_index
