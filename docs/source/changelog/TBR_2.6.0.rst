###########
2.6.0 (TBR)
###########

********
Settings
********

* Mirroring upcoming changes to the maximum lifespan of public certificates, the *default* for validity for
  certificates was changed:

  * :ref:`CA_DEFAULT_EXPIRES <settings-ca-default-expires>` now defaults to 100 days.
  * :ref:`CA_ACME_DEFAULT_CERT_VALIDITY <CA_ACME_DEFAULT_CERT_VALIDITY>` now defaults to 45 days.
  * Note that this only affects the default, you can still change the settings to whatever you want.
  * :ref:`CA_DEFAULT_EXPIRES <settings-ca-default-expires>` and :ref:`CA_ACME_MAX_CERT_VALIDITY
    <CA_ACME_MAX_CERT_VALIDITY>` will be reduced to 47 days in ``django-ca~=4.0.0``.

* Some standard non-string Django settings (like ``ALLOWED_HOSTS``, ``CACHES`` and ``DATABASES``) can now also
  be set with environment variables, see :ref:`Django settings as environment variables
  <settings-env-django-settings>` for more information.
* Boolean settings (e.g. :ref:`CA_ENABLE_ACME <settings-acme-enable-acme>` or :ref:`CA_ENABLE_REST_API
  <settings-ca-enable-rest-api>`) are now parsed using Pydantic model validation. This makes parsing of
  environment variables more strict, as the value is no longer lower-cased and stripped of whitespace. As a
  result, values like ``" true "`` or ``"yEs"`` are no longer recognized.
* ``CA_CUSTOM_APPS`` was removed, it is replaced with :ref:`EXTEND_INSTALLED_APPS
  <settings-extend-installed-apps>` (the setting was deprecated since ``django-ca==2.2.0`` and was even marked
  for removal for ``django-ca==2.5.0`` already).
* The ``CA_DEFAULT_KEY_BACKEND`` setting was removed, as changing the setting can lead to an unexpected
  configurations.

Minor changes
=============

* Raise an error if :ref:`CA_ACME_MAX_CERT_VALIDITY <CA_ACME_MAX_CERT_VALIDITY>` is *lower* then
  :ref:`CA_ACME_DEFAULT_CERT_VALIDITY <CA_ACME_DEFAULT_CERT_VALIDITY>`.
* The (previously undocumented) ``CA_DEFAULT_OCSP_KEY_BACKEND`` setting was removed.

*******************
Setup and packaging
*******************

* Docker images now also load configuration from ``conf/local/``. Previously, this directory was only added
  in the Compose setup.
* The Alpine variant of the Docker image now also sets ``VIRTUAL_ENV`` as environment variable.
* **BACKWARDS INCOMPATIBLE:** For Docker images, the ``DJANGO_CA_STARTUP_REGENERATE_OCSP_KEYS`` environment
  variable was renamed to ``DJANGO_CA_STARTUP_GENERATE_OCSP_KEYS`` for consistency.

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

* The `cache_crls` command was renamed to :command:`manage.py generate_crls` for consistency. The old name
  will be removed in ``django-ca~=3.2.0``.
* The `regenerate_ocsp_keys` command was renamed to :command:`manage.py generate_ocsp_keys` for consistency.
  The old name will be removed in ``django-ca~=3.2.0``.

***************
Admin interface
***************

No changes yet.

************
Celery tasks
************

* The `cache_crl` task was renamed to :py:func:`~django_ca.tasks.generate_crl` for consistency. The old task
  name will be removed in ``django-ca~=3.1.0``.
* The `cache_crls` task was renamed to :py:func:`~django_ca.tasks.generate_crls` for consistency. The old task
  name will be removed in ``django-ca~=3.1.0``.
* **BACKWARDS INCOMPATIBLE:** Arguments to Celery tasks are now passed as Pydantic models, greatly improving
  type safety. This will require you to change your code if you call the task directly.

**********
Python API
**********

No changes yet.

*****
Views
*****

* The `expires` parameter for :py:class:`~django_ca.views.OCSPView` should now be a
  :py:class:`~datetime.timedelta`. Support for passing an ``int`` is deprecated and will be removed in
  ``django-ca~=3.1.0``.

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
