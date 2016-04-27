######
Update
######

*********************
Update from pre 1.0.0
*********************

If you're updating from a version earlier then 1.0.0 (which was the first real
release), you have to reset the migrations. Since all installed instances were
probably private, it made sense to start with a clean state.

To update from an earlier git-checkout, to:

* Upgrade to version 1.0.0b2
* Apply all migrations.
* Upgrade to version 1.0.0
* Remove old migrations from the database::

      python manage.py dbshell
      > DELETE FROM django_migrations WHERE app='django_ca';

* Fake the first migration:

  python manage.py migrate django_ca 0001 --fake
