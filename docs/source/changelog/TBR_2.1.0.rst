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

* :py:func:`CertificateAuthorityManager.init() <django_ca.managers.CertificateAuthorityManager.init>`,
  :py:func:`CertificateManager.create_cert() <django_ca.managers.CertificateManager.create_cert>`  and
  :func:`Profile.create_cert() <django_ca.profiles.Profile.create_cert>` now takes a ``not_after`` parameter,
  replacing ``expires``. The latter is deprecated and will be removed in django-ca 2.3.0.

***************
Database models
***************

* Rename the ``valid_from`` to ``not_before`` and ``expires`` to ``not_after`` to align with the terminology
  used in `RFC 5280`_. The previous read-only property was removed.
