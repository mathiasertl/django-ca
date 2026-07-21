###########
3.2.0 (TBR)
###########

********
Settings
********

No changes yet.

******
ACMEv2
******

No changes yet.

*************
OCSP and CRLs
*************

No changes yet.

********
REST API
********

No changes yet.

************
Command-line
************

* Removed the ``cache_crls`` command (deprecated since ``django-ca==3.0.0``). Use :command:`generate_crls`
  instead.
* Removed the ``regenerate_ocsp_keys`` command (deprecated since ``django-ca==3.0.0``). Use
  :command:`generate_ocsp_keys` instead.

***************
Admin interface
***************

No changes yet.

************
Celery tasks
************

* Removed the ``django_ca.tasks.cache_crl`` task (deprecated since ``django-ca==3.0.0``). Use
  :py:func:`django_ca.tasks.generate_crl` instead.
* Removed the ``django_ca.tasks.cache_crls`` task (deprecated since ``django-ca==3.0.0``). Use
  :py:func:`django_ca.tasks.generate_crls` instead.

**********
Python API
**********

No changes yet.

*****
Views
*****

No changes yet.

***************************
Models and database support
***************************

No changes yet.

************
Dependencies
************

* **BACKWARDS INCOMPATIBLE:** Dropped support for ``cryptography~=46.0``, ``cryptography~=47.0`` and
  ``cryptography~=48.0``.
* **BACKWARDS INCOMPATIBLE:** Dropped support for ``pydantic~=2.12.0``.
* **BACKWARDS INCOMPATIBLE:** Dropped support for ``acme~=5.4.0`` and ``acme~=5.5.0``.

*******************
Deprecation notices
*******************

None yet.

*******************
Setup and packaging
*******************

* Docker images no longer include command-line clients for PostgreSQL and MariaDB, to minimize the attack
  surface. As a consequence, :command:`manage.py dbshell` no longer works out of the box.
