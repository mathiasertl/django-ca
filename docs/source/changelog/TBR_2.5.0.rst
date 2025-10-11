###########
2.5.0 (TBR)
###########

* The :ref:`key_backends_ocsp_db_backend` is now configured by default with the ``db`` alias. It can be used
  with the ``--ocsp-key-backend`` option for :command:`manage.py init_ca` and :command:`manage.py edit_ca`.
* :command:`manage.py regenerate_ocsp_keys` will not stop generating keys if Celery is *not* enabled and an
  error occurs when generating one key.
* Fix validation for ACMEv2 DNS challenges.

********
REST API
********

* The deprecated endpoint `/ca/{ca_serial}/revoke/{certificate_serial}/` for revoking certificates was
  removed (deprecated since ``django-ca==2.3.0``). Use `/ca/{ca_serial}/certs/{certificate_serial}/revoke/`
  instead.

************
Dependencies
************

* Add support for ``pydantic~=2.12``.
* Add support for ``acme~=5.1.0``.
* **BACKWARDS INCOMPATIBLE:** Dropped support for ``acme~=4.1.0``, ``acme~=4.2.0`` and ``josepy~=2.0.0``.

*******************
Deprecation notices
*******************

* This is the last release to support ``acme~=5.0.0``.
