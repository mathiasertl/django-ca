####################
Deprecation timeline
####################


***********
2.2.0 (TBR)
***********

Command-line
============

* Remove support for subjects in OpenSSL-style format (default switched in 2.0.0, deprecated since 1.27.0).

Settings
========

* Support for the old subject format in :ref:`settings-ca-default-subject` and subjects in profiles will be
  removed in 2.2.0 (deprecated since 1.29.0).

Python API
==========

* ``django_ca.utils.get_storage()`` will be removed (deprecated since 2.0).

***********
2.1.0 (TBR)
***********

Views
=====

* Configuring a password in a certificate revocation list view will be removed. Use the ``CA_PASSWORDS``
  setting instead (deprecated since 1.29.0).