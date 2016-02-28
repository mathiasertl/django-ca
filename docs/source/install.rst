Installation
============

You can run **django-ca** as a regular app in any existing Django project of
yours, but if you don't have any Django project running, you can run it as a
`standalone project <#as-standalone-project>`_.

.. WARNING:: Please remember that **django-ca** requires Python3.4+ to run.

As Django app (in an your Django project)
_________________________________________

This chapter assumes that you have an already running Django project and know how
to use it.

You need various development headers for pyOpenSSL, on Debian/Ubuntu systems,
simply install these packages::

   apt-get install gcc python3-dev libffi-dev libssl-dev

You can install **django-ca** simply via pip::

   pip install django-ca

and add it to your ``INSTALLED_APPS``::

   INSTALLED_APPS = [
      # ... your other apps...

      'django_ca',
   ]

... and configure the :doc:`other available settings <settings>` to your
liking, then simply run::

   python manage.py migrate
   python manage.py collectstatic

   # FINALLY, create the root certificates for your CA:
   #     (replace parameters after init_ca with your local details)
   python manage.py init_ca "Root CA" AT Vienna Vienna Org OrgUnit ca.example.com

After that, **django-ca** should show up in your admin interface and provide
various ``manage.py`` commands (see :doc:`manage_commands`).

.. _as-standalone:

As standalone project
_____________________

In this variant, you can run **django-ca** stand-alone. You can use the project
strictly from the command line, the webinterface is completely optional.

In the following code-snippet, you'll do all necessary steps to get a basic
setup::

   # install dependencies (adapt to your distro):
   apt-get install gcc git python3-dev libffi-dev libssl-dev virtualenv

   # clone git repository:
   git clone https://github.com/mathiasertl/django-ca.git

   # create virtualenv:
   cd django-ca
   virtualenv -p /usr/bin/python3 .
   source bin/activate

   # install Python dependencies:
   pip install -U pip setuptools
   pip install -r requirements.txt

In the above script, you have created a `virtualenv
<http://docs.python-guide.org/en/latest/dev/virtualenvs/>`_, meaning that all
libraries you install with ``pip install`` are installed in the virtualenv (and
don't pollute your system). It also means that before you execute any
``manage.py`` commands, you'll have to activate your virtualenv, by doing, in
the directory of the git checkout::

   source bin/activate

Before you continue, you have to configure **django-ca**. Django uses a file
called ``settings.py``, but so you don't have to change any files managed by
git, it includes ``localsettings.py`` in the same directory. So copy the
example file and edit it with your favourite editor::

   cp ca/ca/localsettings.py.example ca/ca/localsettings.py

The most important settings are documented there, but you can of course use any
setting `provided by Django
<https://docs.djangoproject.com/en/dev/topics/settings/>`_. After you have
configured **django-ca** (especially ``DATABASES`` and, if you intend to use
the webinterface, ``STATIC_ROOT``), you need to run a few ``manage.py``
commands::

   python ca/manage.py migrate

   # if you intend to run the webinterface
   python ca/manage.py collectstatic

   # FINALLY, create the root certificates for your CA:
   #     (replace parameters after init_ca with your local details)
   python manage.py init_ca AT Vienna Vienna Org OrgUnit ca.example.com

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

   ${PYTHON} ${MANAGE} $@

Setup a webserver
-----------------

Setting up a webserver and all that comes with it is really out of scope of
this document. The WSGI file is located in ``ca/ca/wsgi.py``. Django itself
provides some info for using `Apache and mod_wsgi
<ttps://docs.djangoproject.com/en/dev/topics/install/#install-apache-and-mod-wsgi>`_,
or you could use `uWSGI and nginx
<http://uwsgi-docs.readthedocs.org/en/latest/tutorials/Django_and_nginx.html>`_,
or any of the many other options available.

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
