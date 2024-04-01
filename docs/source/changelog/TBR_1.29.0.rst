############
1.29.0 (TBR)
############

* Removed support for the ``cn_in_san`` parameter in profiles.

************
Dependencies
************

* **BACKWARDS INCOMPATIBLE:** Dropped support for Python 3.8.
* **BACKWARDS INCOMPATIBLE:** Dropped support for ``cryptography~=41.0``, ``acme~=2.7.0`` and ``acme~=2.8.0``.

**********
Python API
**********

* **BACKWARDS INCOMPATIBLE:** Removed ``django_ca.utils.parse_hash_algorithm()``, deprecated since
  ``django-ca==1.25.0``. Use :py:attr:`standard hash algorithm names <django_ca.typehints.HashAlgorithms>`
  instead.
* **BACKWARDS INCOMPATIBLE:** Removed ``django_ca.utils.format_name()``, deprecated since
  ``django-ca==1.27.0``. Use RFC 4514-formatted subjects instead.
