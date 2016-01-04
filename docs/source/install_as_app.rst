Install as Django app (in your existing Django project)
=======================================================

This page assumes that you have an already running Django project and know how
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

After that, **django-ca** should show up in your admin interface and provide
various ``manage.py`` commands.
