###########
3.3.0 (TBR)
###########

.. spelling::

    bytecode

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

* :command:`manage.py notify_expiring_certs`: The ``--days`` parameter was removed.

***************
Admin interface
***************

No changes yet.

************
Celery tasks
************

No changes yet.

**********
Python API
**********

* :func:`django_ca.managers.CertificateAuthorityManager.init`: The `acme_enabled`, `acme_registration` and
  `acme_requires_contact` parameters now support and default to `None`, preserving the models default.

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

* Add support for Python 3.15.
* **BACKWARDS INCOMPATIBLE:** Dropped support for ``cryptography~=49.0``.
* **BACKWARDS INCOMPATIBLE:** Dropped support for ``acme~=5.6.0`` and ``acme~=5.7.0``.

*******************
Deprecation notices
*******************

* This is the last version to support ``Python~=3.11.0``.
* This is the last version to support DSA keys (cryptography is also deprecating and eventually removing
  support).
* This is the last version to support Alpine-based Docker images.
* Docker images: This is the last version to support the old shell-based wrapper scripts (``celery.sh``,
  ``celerybeat.sh`` and ``gunicorn.sh``). Find the new python-based equivalents below.

*******************
Setup and packaging
*******************

Docker images
=============

* **Security:** SBOMs are now included in GitHub images. Previously, only `ghcr.io`-hosted images included it.
* Wrapper scripts for starting Gunicorn and Celery where translated to Python under new names:

  ================= ========================
  Old name          New name
  ================= ========================
  ``celerybeat.sh`` ``django-ca-celerybeat``
  ``celery.sh``     ``django-ca-celery``
  ``gunicorn.sh``   ``django-ca-gunicorn``
  ================= ========================

  Old names will be removed in the next release.

* Python is now installed via `uv` and are based on the plain Debian image. This is in preparation for using
  "distroless" images.
* Bytecode is not included for improved startup times (at the expense of larger images). The bytecode adds
  about 120 MB to the image size (227 MB ->345 MB), but startup time of a simple ``manage -h`` invocation
  improves from six seconds to 1.5 seconds.
