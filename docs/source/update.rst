######
Update
######

Since 1.0.0, this project updates like any other project. First, update the source code, if you use git:

.. code-block:: console

   $ git pull origin master

or if you installed **django-ca** via pip:

.. code-block:: console

   $ pip install -U django-ca

then upgrade with these commands:

.. code-block:: console

   $ pip install -U -r requirements.txt
   $ python ca/manage.py migrate

   $ python ca/manage.py collectstatic  # if you use the webinterface

.. WARNING::

   If you installed **django-ca** in a virtualenv, don't forget to activate it before executing any
   python or pip commands using::

      source bin/activate

.. _update_114:

*************************
Update to 1.14.0 or later
*************************

**django-ca** has changed the layout of the :ref:`CA_PROFILES <settings-ca-profiles>`, you have to update any
any custom setting according to the :ref:`migration instructions <profiles-pre-114-migration>`.

The old profile settings will be supported until (and including) version 1.16.

.. _update-file-storage:

*************************
Update to 1.12.0 or later
*************************

.. NOTE::

   The ``migrate_ca`` command has been removed in django-ca 1.15.0. If you update to version 1.15.0 or later,
   you first have to upgrade to 1.14.0 and run ``manage.py migrate_ca``.

:ref:`Version 1.12.0 <changelog-1.12.0>` and later uses the `File storage API
<https://docs.djangoproject.com/en/2.1/ref/files/storage/>`_ to store files.
Before 1.12.0, django-ca stored absolute file paths in the database.

If you also want to switch to a different storage system (e.g. from `django-storages
<https://django-storages.readthedocs.io/>`_), switch to relative paths everywhere first, then migrate to the
new storage system by configuring :ref:`CA_FILE_STORAGE <settings-ca-file-storage>` and copying all files to
the new location.

The old way of accessing files works until (and including) version 1.14.

Migrate CAs
===========

In most cases, you will be able to migrate using a simple manage.py command:

.. code-block:: console

   $ python manage.py migrate_ca
   <serial>: Updating <old path> to <new path>.

If you have stored some private keys outside of the file system, you will need to force them being moved into
the directory configured by :ref:`CA_DIR <settings-ca-dir>`:

.. code-block:: console

   $ python manage.py migrate_ca
   <serial>: <old path> is not in a subdir of <CA dir>. Use --force to move files.
   $ python manage.py migrate_ca --force
   <serial>: Move <old path> to <CA dir>.

Note that this command can safely be executed multiple times if some migrations didn't work (e.g. because of
missing permissions) the first time.

Migrate OCSP responder
======================

If you have configured a manual OCSP responder, you have to move the files into the directory referenced by
:ref:`CA_DIR <settings-ca-dir>` (if they're not there already) and update ``responder_key`` and
``responder_cert`` to a relative path.

You can test your configuration change invoking ``python manage.py shell`` and running:

.. code-block:: python

   >>> import os
   >>> from django_ca import ca_settings
   >>> from django_ca.utils import read_file
   >>> ca_settings.CA_DIR
   '/home/example/django-ca/ca/files'
   >>> responder_key = 'responder/responder.key'  # this the same as "responder_key" in your OCSP view
   >>> absolute_path = os.path.join(ca_settings.CA_DIR, responder_key)
   >>> os.path.exists(absolute_path)  # test that <CA_DIR>/<responder_key> exists
   True
   >>> read_file(responder_key)
   '-----BEGIN CERTIFICATE-----
   ...'


*******************
Update from 1.0.0b2
*******************

If you're updating from a version earlier then 1.0.0 (which was the first real
release), you have to first update to 1.0.0.b1 (see below), then to 1.0.0.b2,
apply all migrations and reset existing migrations Since all installed instances
were probably private, it made sense to start with a clean state.

To update from an earlier git-checkout, to:

* Upgrade to version 1.0.0b2
* Apply all migrations.
* Upgrade to version 1.0.0
* Remove old migrations from the database:

  .. code-block:: console

     $ python manage.py dbshell
     > DELETE FROM django_migrations WHERE app='django_ca';

* Fake the first migration:

  .. code-block:: console

     $ python manage.py migrate django_ca 0001 --fake

**************************
Update from before 1.0.0b1
**************************

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
