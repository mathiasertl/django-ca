#############
Web interface
#############

The web interface allows you to perform the most common tasks necessary when running certificate authority. It
is implemented using Djangos admin interface. You can:

* Issue and revoke certificates.
* Modify the x509 extensions used when signing certificates.
* Modify who is notified about expiring certificates.

The django project in the git repository (e.g. if you installed **django-ca** as :ref:`a standalone project
<as-standalone>`) already enables the admin interface and it's usable as soon as you enabled the web server
(tip: Create a user for login using ``manage.py createsuperuser``). If you installed **django-ca** as an app,
the admin interface is automatically included.
