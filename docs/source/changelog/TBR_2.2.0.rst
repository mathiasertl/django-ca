###########
2.2.0 (TBR)
###########

***********
Performance
***********

* Optimize number of database queries in performance-sensitive views (OCSP, CRLs, ACMEv2).

**********************
Command-line utilities
**********************

* Drop support for old OpenSSL-style subject formats in :command:`manage.py init_ca`,
  :command:`manage.py sign_cert` and :command:`manage.py resign_cert`` (default switched in 2.0.0,
  deprecated since 1.27.0). Use RFC 4514 subjects instead.

********
Settings
********

* Dropped support for the old subject format in :ref:`settings-ca-default-subject` and subjects in profiles
  (deprecated since 1.29.0).

************
Dependencies
************

* **BACKWARDS INCOMPATIBLE:** Dropped support for ``django~=5.0.0``, ``cryptography~=43.0``, ``acme~=2.11.0``
  and ``pydantic~=2.9.0``.

**********
Python API
**********

* ``django_ca.utils.get_storage()`` was be removed (deprecated since 2.0).

*******************
Deprecation notices
*******************

* ``django_ca.extensions.parse_extension()`` is deprecated and will be removed in ``django-ca==2.3.0``. Use
  :doc:`Pydantic models </python/pydantic>` instead.
* Functions related to the old OpenSSL style subject format are deprecated and will be removed in
  ``django_ca==2.3.0``:

  * ``django_ca.utils.parse_name_x509()``
  * ``django_ca.utils.parse_serialized_name_attributes()``
  * ``django_ca.utils.serialize_name()``
  * ``django_ca.utils.split_str()``
  * ``django_ca.utils.x509_name()``
