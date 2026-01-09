###########
2.6.0 (TBR)
###########

********
Settings
********

* Boolean settings (e.g. :ref:`CA_ENABLE_ACME <settings-acme-enable-acme>` or :ref:`CA_ENABLE_REST_API
  <settings-ca-enable-rest-api>`) are now parsed using Pydantic model validation. This makes parsing of
  environment variables more strict, as the value is no longer lower-cased and stripped of whitespace. As a
  result, values like ``" true "`` or ``"yEs"`` are no longer recognized.
* ``CA_CUSTOM_APPS`` was removed, it is replaced with :ref:`EXTEND_INSTALLED_APPS
  <settings-extend-installed-apps>` (the setting was deprecated since ``django-ca==2.2.0`` and was even marked
  for removal for ``django-ca==2.5.0`` already).

*******************
Setup and packaging
*******************

* Docker images now also load configuration from ``conf/local/``. Previously, this directory was only added
  in the Compose setup.
* The Alpine variant of the Docker image now also sets ``VIRTUAL_ENV`` as environment variable.

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

No changes yet.

***************
Admin interface
***************

No changes yet.

************
Celery tasks
************

* Arguments to Celery tasks are now passed as Pydantic models, greatly improving type safety.

**********
Python API
**********

No changes yet.

************
Dependencies
************

* **BACKWARDS INCOMPATIBLE:** Dropped support for Python 3.10.
* **BACKWARDS INCOMPATIBLE:** Dropped support for ``cryptography~=45.0``.
* **BACKWARDS INCOMPATIBLE:** Dropped support for ``pydantic~=2.11.0``.
* **BACKWARDS INCOMPATIBLE:** Dropped support for ``acme~=5.0.0`` and ``acme~=5.1.0``.
* **BACKWARDS INCOMPATIBLE:** Dropped support for ``josepy~=2.1.0``.
* **BACKWARDS INCOMPATIBLE:** Dropped support for Alpine 3.20 and Alpine 3.21.
* **BACKWARDS INCOMPATIBLE:** Dropped support for Debian 11 (Bullseye) and Debian 12 (Bookworm).
* **BACKWARDS INCOMPATIBLE:** Dropped support for Ubuntu 25.04 (Plucky Puffin).

*******************
Deprecation notices
*******************

None yet.
