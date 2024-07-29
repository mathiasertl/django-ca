###########
2.0.0 (TBR)
###########

**********************
Command-line utilities
**********************

* Subjects are now parsed in the RFC 4514 format by default. Subjects in the OpenSSL-style format are still
  supported via the ``--subject-format=openssl`` option, but support for it will be removed in 2.0.0.
* Removed the ``convert_timestamps`` command (deprecated since 1.28.0).

************
Dependencies
************

* Add support for Pydantic 2.8.
* **BACKWARDS INCOMPATIBLE:** Dropped support for ``pydantic<2.7.0``, ``acme~=2.9.0`` and ``Celery~=5.3.0``.
* Drop support for Alpine 3.17.

**********
Python API
**********

* :py:func:`~django_ca.utils.parse_encoding` no longer accepts an already parsed Encoding.
* ``django_ca.utils.parse_expires()`` and ``django_ca.utils.parse_key_curve`` where removed.
* :py:func:`CertificateAuthorityManager.objects.init() <django_ca.managers.CertificateAuthorityManager.init>`
  no longer accepts ``int`` or ``timedelta`` for expires. Pass a timezone-aware object instead.
* :py:class:`~django_ca.profiles.Profile` no longer accepts unparsed extension values:

  * An ``int`` for `expires` - pass a ``timedelta`` instead.
  * A ``str`` or iterable of ``str``-tuples for `subject` - pass a :py:class:`~cryptography.x509.Name`
    instead.
  * Deprecated extensions formats in `extensions`.

  Note that this does not affect configuration in settings, as these values are parsed before passed to this
  class.

* :py:func:`~django_ca.profiles.Profile.create_cert` no longer accepts ``int`` for expires. Pass a
  ``timedelta`` instead.

*******************
Deprecation notices
*******************

* ``django_ca.utils.get_storage()`` will be removed in 2.2.0.
