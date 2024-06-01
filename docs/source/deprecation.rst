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

***********
2.1.0 (TBR)
***********

Views
=====

* Configuring a password in a certificate revocation list view will be removed. Use the ``CA_PASSWORDS``
  setting instead (deprecated since 1.29.0).

***********
2.0.0 (TBR)
***********

Command-line
============

* Switch the default subject format from OpenSSL-style to RFC 4514 (OpenSSL-style format will be removed in
  2.2.0, announced in 1.27.0).
* The :command:`manage.py convert_timestamps` command will be removed (deprecated since 1.28.0).

Profiles
========

* Support for the old extension format in profiles will be removed. See :ref:`profiles-extensions` for the new
  format.

Settings
========

* The ``CA_FILE_STORAGE`` and ``CA_FILE_STORAGE_KWARGS`` settings will be removed. Use
  :ref:`settings-ca-key-backends` instead (deprecated since 1.28.0).

Packaging
=========

* The ``psycopg3`` extra will be removed.

Python API
==========

* :py:func:`django_ca.managers.CertificateAuthorityManager.init` will stop accepting ``int`` or ``timedelta``
  for `expires`.
* :py:func:`django_ca.managers.CertificateManager.create_cert` will stop accepting ``int`` for `expires`.
* ``django_ca.extensions.parse_extension()`` will be removed. Use Pydantic models instead (deprecated since
  1.29.0).
* ``django_ca.extensions.parse_key_curve()`` will be removed (deprecated since 1.29.0).

*************************
1.29.0 (Upcoming release)
*************************

Dependencies
============

* Dropped support for Python 3.8.
* Dropped support for ``cryptography~=41.0``, ``acme~=2.7.0`` and ``acme~=2.8.0``.

Python API
==========

* :py:func:`django_ca.managers.CertificateAuthorityManager.init`:

  * The `expires` parameter is now mandatory, and should be a timezone-aware datetime.
  * The `extensions` parameter no longer accepts extensions that are not valid for certificates.

* :py:func:`django_ca.managers.CertificateManager.create_cert`:

  * The `expires` parameter is now mandatory, and should be a timezone-aware datetime or a ``timedelta``.
  * The `extensions` parameter no longer accepts extensions that are not valid for end entity certificates.

* Removed ``django_ca.utils.parse_hash_algorithm()``, deprecated since 1.25.0. Use
  :py:attr:`standard hash algorithm names <django_ca.typehints.HashAlgorithms>` instead.
* Removed ``django_ca.utils.format_name()``, deprecated since 1.27.0. Use RFC 4514-formatted subjects instead.

*******************
1.28.0 (2024-03-30)
*******************

Dependencies
============

* Dropped support for ``Django~=3.2``, ``acme==1.26.0`` and ``Alpine~=3.16``.
