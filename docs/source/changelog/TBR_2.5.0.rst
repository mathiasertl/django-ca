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

* No longer include the username when viewing a certificate order.
* Ensure that a user can only view certificate orders that were created by themself.
* The deprecated endpoint `/ca/{ca_serial}/revoke/{certificate_serial}/` for revoking certificates was
  removed (deprecated since ``django-ca==2.3.0``). Use `/ca/{ca_serial}/certs/{certificate_serial}/revoke/`
  instead.

*************
Docker images
*************

* The Docker images have been updated to use Python 3.14.
* Docker images are now uniquely tagged using a datestamp, not an increasing integer. This simplifies
  automatic image updates.

************
Dependencies
************

* **BACKWARDS INCOMPATIBLE:** Dropped support for ``acme~=4.1.0``, ``acme~=4.2.0`` and ``josepy~=2.0.0``.
* Add support for Python 3.14.
* Add support for ``pydantic~=2.12``.
* Add support for ``acme~=5.1.0``.

*******************
Deprecation notices
*******************

* This is the last release to support Python 3.10 and Python 3.11.
* This is the last release to support ``pydantic~=2.11.0``.
* This is the last release to support ``acme~=5.0.0``.
* This is the last release to support Alpine 3.20.
* This is the last release to support Debian 11 (Bullseye).
