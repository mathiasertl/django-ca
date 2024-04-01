############
1.29.0 (TBR)
############

********
Profiles
********

* Extensions in profiles now use the same syntax as in the API. This change only affects extensions usually
  not set via profiles, such as the CRL Distribution Points or Authority Information Access extensions.
  See :ref:`profiles-extensions` for the new format. Support for the old format will be removed in 2.0.0.
* **BACKWARDS INCOMPATIBLE:** Removed support for the ``cn_in_san`` parameter in profiles (deprecated since
  1.28.0).

************
Dependencies
************

* **BACKWARDS INCOMPATIBLE:** Dropped support for Python 3.8.
* **BACKWARDS INCOMPATIBLE:** Dropped support for ``cryptography~=41.0``, ``acme~=2.7.0`` and ``acme~=2.8.0``.

**********
Python API
**********

* Add literal typehints for extension keys under :py:attr:`~django_ca.typehints.ExtensionKeys` and
  :py:attr:`~django_ca.typehints.CertificateExtensionKeys` to improve type hinting.
* Add :py:attr:`~django_ca.constants.CERTIFICATE_EXTENSION_KEYS`, a subset of
  :py:attr:`~django_ca.constants.EXTENSION_KEYS`, for extensions all extensions that may occur in
  end-entity certificates.
* **BACKWARDS INCOMPATIBLE:** Removed ``django_ca.utils.parse_hash_algorithm()``, deprecated since
  1.25.0. Use :py:attr:`standard hash algorithm names <django_ca.typehints.HashAlgorithms>` instead.
* **BACKWARDS INCOMPATIBLE:** Removed ``django_ca.utils.format_name()``, deprecated since 1.27.0. Use RFC
  4514-formatted subjects instead.
* **BACKWARDS INCOMPATIBLE:** Removed the `password` parameter to
  :py:func:`~django_ca.models.CertificateAuthority.sign`. It was a left-over and only used in the signal.

*******
Signals
*******

* :py:attr:`django_ca.signals.pre_sign_cert` now receives `key_backend_options` instead of `password`.

*******************
Deprecation notices
*******************

* Support for the old extension format in profiles will be removed in 2.0.0.
* ``django_ca.extensions.parse_extension()`` will be removed in 2.0.0. Use Pydantic models instead.
