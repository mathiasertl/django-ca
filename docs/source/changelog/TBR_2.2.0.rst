###########
2.2.0 (TBR)
###########

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
