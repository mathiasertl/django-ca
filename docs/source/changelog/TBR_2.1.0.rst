###########
2.1.0 (TBR)
###########

************
Dependencies
************

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

***************
Database models
***************

* Rename the ``valid_from`` to ``not_before`` and ``expires`` to ``not_after`` to align with the terminology
  used in `RFC 5280`_. The previous read-only property was removed.
