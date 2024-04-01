############
1.29.0 (TBR)
############

********
Profiles
********

* Extensions in profiles now use the same syntax as in the API. This change only affects extensions usually
  not set via profiles, such as the CRL Distribution Points or Authority Information Access extensions.
  See :ref:`profiles-extensions` for the new format. Support for the old format will be removed in 2.0.0.
* **BACKWARDS INCOMPATIBLE:** Removed support for the ``cn_in_san`` parameter in profiles (deprecated since
  1.28.0).

************
Dependencies
************

* **BACKWARDS INCOMPATIBLE:** Dropped support for Python 3.8.
* **BACKWARDS INCOMPATIBLE:** Dropped support for ``cryptography~=41.0``, ``acme~=2.7.0`` and ``acme~=2.8.0``.

**********
Python API
**********

* **BACKWARDS INCOMPATIBLE:** Removed ``django_ca.utils.parse_hash_algorithm()``, deprecated since
  1.25.0. Use :py:attr:`standard hash algorithm names <django_ca.typehints.HashAlgorithms>` instead.
* **BACKWARDS INCOMPATIBLE:** Removed ``django_ca.utils.format_name()``, deprecated since 1.27.0. Use RFC
  4514-formatted subjects instead.

*******************
Deprecation notices
*******************

* Support for the old extension format in profiles will be removed in 2.0.0.
* ``django_ca.extensions.parse_extension()`` will be removed in 2.0.0. Use Pydantic models instead.
