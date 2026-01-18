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
  be set with environment variables, see :ref:`settings-project-3rd-party` for more information.
* Boolean settings (e.g. :ref:`CA_ENABLE_ACME <settings-acme-enable-acme>` or :ref:`CA_ENABLE_REST_API
  <settings-ca-enable-rest-api>`) are now parsed using Pydantic model validation. This makes parsing of
  environment variables more strict, as the value is no longer lower-cased and stripped of whitespace. As a
  result, values like ``" true "`` or ``"yEs"`` are no longer recognized.
* `EXTEND_*` settings from environment variables no longer override settings from files.
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

* CRLs are now only regenerated if they expire within a renewal interval, similar to OCSP keys. This enables
  running the task to generate CRLs much more frequently and only re-generating CRLs when required.
* Celery tasks and management commands now accept key backend options when acting on a single CA and an
  `exclude` parameter to exclude CAs. This allows you to exclude CAs that require special key backend options
  (e.g. a password) from the default periodic task, and adding an additional, dedicated periodic task with key
  backend options for that CA.

********
REST API
********

No changes yet.

************
Command-line
************

* **BACKWARDS INCOMPATIBLE:** The `dump_ca` and `dump_cert` commands where removed (deprecated since 2.4.0).
* The `cache_crls` command was renamed to :command:`manage.py generate_crls` for consistency. The old name
  will be removed in ``django-ca~=3.2.0``.
* The `regenerate_ocsp_keys` command was renamed to :command:`manage.py generate_ocsp_keys` for consistency.
  The old name will be removed in ``django-ca~=3.2.0``.
* :command:`manage.py generate_crls` now allows passing key backend options if exactly one CA is specified.
* :command:`manage.py generate_crls` and :command:`manage.py generate_ocsp_keys` now use a unified interface
  and have the same arguments.
* :command:`manage.py generate_crls` and :command:`manage.py generate_ocsp_keys` now allow forcing generation
  of CRLs/OCSP keys (even if not due for renewal) and excluding CAs from renewal.

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
* :py:func:`~django_ca.tasks.generate_crls` and :py:func:`~django_ca.tasks.generate_ocsp_keys` now support
  the `force` parameter to force generating CRLs/OCSP keys, even if not due for renewal.
* :py:func:`~django_ca.tasks.generate_crls` and :py:func:`~django_ca.tasks.generate_ocsp_keys` now support
  the `exclude` parameter to exclude CAs from generating CRLs/OCSP keys.


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
