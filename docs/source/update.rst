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
any custom setting. Please see documentation for django-ca 1.16 for more detailed instructions.

The old profile settings will be supported until (and including) version 1.16.

.. _update-file-storage:

*************************
Update to 1.12.0 or later
*************************

Please see documentation for previous versions on documentation how to upgrade.
