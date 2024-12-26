###########
2.1.0 (TBR)
###########

************
Docker image
************

* The main Docker image is now based off Debian instead of Alpine. The Alpine image is still provided with the
  ``-alpine`` suffix (e.g. ``mathiasertl/django-ca:2.1.0-alpine``).

****************************
Certificate Revocation Lists
****************************

* Certificate Revocation Lists (CRLs) are now stored in the database via the
  :class:`~django_ca.models.CertificateRevocationList` model. This makes CRLs more robust, as clearing the
  cache will no longer cause an error.

*******************
OCSP responder keys
*******************

* Private keys for OCSP responders are now stored using configurable backends, just like private keys for
  certificate authorities. See :ref:`ocsp_key_backends` for more information.
* Add a :ref:`key_backends_ocsp_hsm_backend` to allow storing OCSP keys in a HSM (Hardware Security Module).
* Add a :ref:`key_backends_ocsp_db_backend` to allow storing OCSP keys in the database.

************
Key backends
************

* Add a :ref:`db_backend` to allow storing private keys in the database. This backend makes the private key
  accessible to any frontend-facing web server and is thus less secure then other backends, but is an
  option if your environment has no file system available.
* Remove the ``get_ocsp_key_size()` and ``get_ocsp_key_elliptic_curve`` from the core key backend interface,
  as they are now handled by :ref:`ocsp_key_backends`.

**********************
Command-line utilities
**********************

* Add the ``--only-some-reasons`` parameter to :command:`manage.py dump_crl`.
* The ``--scope`` parameter to :command:`manage.py dump_crl` is deprecated and will be removed in django-ca
  2.3.0. Use ``--only-contains-ca-certs``, ``--only-contains-user-certs`` or
  ``--only-contains-attribute-certs`` instead.
* **BACKWARDS INCOMPATIBLE:**  The ``--algorithm`` parameter to :command:`manage.py dump_crl` no longer has
  any effect and will be removed in django-ca 2.3.0.

********
REST API
********

* When requesting a new certificate, validate the submitted CSR before relaying the order to the backend
  (fixes `#152 <https://github.com/mathiasertl/django-ca/issues/152>`_).
* Support for the :py:class:`Admissions extension <django_ca.pydantic.extensions.AdmissionsModel>` when
  ``cryptography>=44`` is used.

********
Settings
********

* The `encodings` parameter to :ref:`settings-ca-crl-profiles` was removed. Both encodings are now always
  available.
* The `scope` parameter to :ref:`settings-ca-crl-profiles` is now deprecated in favor of the
  `only_contains_ca_certs`, `only_contains_user_certs` and `only_some_reasons` parameters. The old parameter
  currently still takes precedence, but will be removed in django-ca 2.3.0.

************
Dependencies
************

* Add support for Python 3.13, ``cryptography~=44.0`` and ``pydantic~=2.10.0``.
* **BACKWARDS INCOMPATIBLE:** Dropped support for ``pydantic~=2.7.0``, ``pydantic~=2.8.0``,
  ``cryptography~=42.0`` and ``acme~=2.10.0``.

**********
Python API
**********

* Functions that create a certificate now take a ``not_after`` parameter, replacing ``expires``. The
  ``expires`` parameter  is deprecated and will be removed in django-ca 2.3.0. The following functions are
  affected:

  * :func:`django_ca.models.CertificateAuthority.sign`
  * :func:`django_ca.models.CertificateAuthority.generate_ocsp_key`
  * :func:`django_ca.managers.CertificateAuthorityManager.init`
  * :func:`django_ca.managers.CertificateManager.create_cert`
  * :func:`django_ca.profiles.Profile.create_cert`

* :func:`~django_ca.utils.get_crl_cache_key` added the `only_contains_ca_certs`, `only_contains_user_certs`,
  `only_contains_attribute_certs` and `only_some_reasons` arguments.
* **BACKWARDS INCOMPATIBLE:** The `scope` argument for :func:`~django_ca.utils.get_crl_cache_key` was removed.
  Use the parameters described above instead.

***************
Database models
***************

* Rename the ``valid_from`` to ``not_before`` and ``expires`` to ``not_after`` to align with the terminology
  used in `RFC 5280`_. The previous read-only property was removed.
* Add the :class:`~django_ca.models.CertificateRevocationList` model to store generated CRLs.
* :func:`django_ca.models.CertificateAuthority.get_crl_certs` and
  :func:`django_ca.models.CertificateAuthority.get_crl` are deprecated and will be removed in django-ca 2.3.0.
* **BACKWARDS INCOMPATIBLE:** The `algorithm`, `counter`, `full_name`, `relative_name` and
  `include_issuing_distribution_point` parameters for :func:`django_ca.models.CertificateAuthority.get_crl`
  no longer have any effect.

*****
Views
*****

* The :class:`~django_ca.views.CertificateRevocationListView` has numerous updates:

  * **BACKWARDS INCOMPATIBLE:** The `password` parameter was removed. Use the
    :ref:`CA_PASSWORDS <settings-ca-passwords>` setting instead (deprecated since django-ca 1.29.0).
  * The `expires` parameter now has a default of ``86400`` (from ``600``) to align with defaults elsewhere.
  * The `scope` parameter is deprecated and will be removed in django-ca 2.3.0. Use `only_contains_ca_certs`
    and `only_contains_user_certs` instead.
  * The `include_issuing_distribution_point` no longer has any effect and will be removed in django-ca 2.3.0.

*******************
Deprecation notices
*******************

Please also see the :doc:`deprecation timeline </deprecation>` for previous deprecation notices.

* This will be the last release to support ``django~=5.0.0``, ``cryptography~=43.0`` and ``pydantic~=2.9.0``.
* Support for Python 3.9 and ``django~=4.2.0`` will be dropped in ``django-ca==2.3.0``.
