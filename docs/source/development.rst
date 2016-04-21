###########
Development
###########

**********
Setup demo
**********

You can set up a demo using ``fab init_demo``. First create a minimal
``localsettings.py`` file (in ``ca/ca/localsettings.py``)::

   DEBUG = True
   SECRET_KEY = "whatever"

And then simply run ``fab init_demo`` from the root directory of your project.

*****************************
Development webserver via SSL
*****************************

To test a certificate in your webserver, first install the root certificate
authority in your browser, then run ``stunnel4`` and ``manage.py runserver`` in
two separate shells::

   stunnel4
   HTTPS=1 python manage.py runserver 8001

Then visit https://localhost:8443.
