######
Update
######

Since 1.0.0, this project updates like any other project. First, update the source code, if you use git::

   git pull origin master

and if you are on pip::

   pip install -U django-ca

then upgrade with these commands::

   pip install -U -r requirements.txt
   python ca/manage.py migrate

   # if you use the webinterface
   python ca/manage.py collectstatic

*****************
Update to 1.0.0b2
*****************

If you're updating from a version earlier then 1.0.0 (which was the first real
release), you have to first update to 1.0.0.b1 (see below), then to 1.0.0.b2,
apply all migrations and reset existing migrations Since all installed instances
were probably private, it made sense to start with a clean state.

To update from an earlier git-checkout, to:

* Upgrade to version 1.0.0b2
* Apply all migrations.
* Upgrade to version 1.0.0
* Remove old migrations from the database::

      python manage.py dbshell
      > DELETE FROM django_migrations WHERE app='django_ca';

* Fake the first migration:

  python manage.py migrate django_ca 0001 --fake

***********************
Update from pre 1.0.0b1
***********************

Prior to 1.0.0, this app was not intended to be reusable and so had a generic name. The app was
renamed to `django_ca`, so it can be used in other Django projects (or hopefully stand-alone,
someday). Essentially, the upgrade path should work something like this:

.. code-block:: bash

   # backup old data:
   python manage.py dumpdata certificate --indent=4 > certs.json

   # update source code
   git pull origin master

   # create initial models in the new app, but only the initial version!
   python manage.py migrate django_ca 0001

   # update JSON with new model name
   sed 's/"certificate.certificate"/"django_ca.certificate"/' > certs-updated.json

   # load data
   python manage.py loaddata certs-updated.json

   # apply any other migrations
   python manage.py migrate
