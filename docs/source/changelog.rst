#########
ChangeLog
#########

.. _changelog-head:

.. _changelog-1.28.0:

************
1.28.0 (TBR)
************

.. NOTE::

   django-ca 1.27.0 introduced a major change in how subjects are parsed on the command-line. Please see
   :ref:`update_126_rfc4514_subjects` for migration information.

* Add support for ``Django~=5.0``, ``cryptography~=42``, ``acme==2.8.0`` and ``acme==2.9.0``.
* ``pydantic>=2.5`` is now a required dependency.
* The ``CA_FILE_STORAGE`` and ``CA_FILE_STORAGE_KWARGS`` settings are deprecated in favor of
  :ref:`settings-ca-key-backends`. Installations :doc:`as Django app <quickstart_as_app>` must add a
  ``"django-ca"`` storage alias in their configuration.
* Private keys (for CAs and OCSP responder certificates) are now stored as DER keys to improve loading speed.
* The admin interface now presents lists of general names (e.g. in the Subject Alternative Name extension) as
  a list of order-able key/value pairs when adding certificates.
* Extensions added by the CA when signing new certificates can now have the same complexity as when giving
  the extensions directly when signing the certificate.

  * The ``--sign-ca-issuer``, ``--sign-ocsp-responder`` and ``--sign-issuer-alternative-name`` options to
    :command:`manage.py sign_cert` etc. now support any general name type and giving multiple general names.
  * The CRL Distribution Points extension added to certificates may now be marked as critical via
    ``--sign-crl-distribution-points-critical``.
  * When editing a CA, the admin interface presents these fields in the same way as when signing a
    certificate.

* Remove the option to add the Common Name to the Subject Alternative Name extension, as the result is
  unpredictable:

  * The :command:`manage.py sign_cert` ``--cn-in-san`` option was removed.
  * The checkbox in the admin interface was removed.
  * The profile option no longer has any effect and issues a warning.

* Add :doc:`Pydantic models for cryptography classes <python/pydantic>`. These are required for the REST API,
  but are also used internally for various places where serialization of objects is required.
* Support for configuring absolute paths for OCSP responder certificates in manual OCSP views was removed.
  This was a left over, it was deprecated and issued a warning since 2019.


REST API changes
================

.. NOTE:: The :doc:`rest_api` is still experimental and endpoints will change without notice.

The update to django-ninja 1.1 and Pydantic brings a general update on how extensions are represented. Any
code using the API will have to be updated.

* Update to ``django-ninja==1.1.0``, including a full migration to Pydantic 2.
* The format of extensions now includes a ``type`` parameter indicating the extension type.
* Extension objects are now more in line with `RFC 5280`_ and no longer use arbitrary abbreviations.
* Extensions are now represented as a list.
* General names are now represented as an object, instead of string that has to be parsed.

Backwards incompatible changes
==============================

* Drop support for ``Django~=3.2``, ``acme==1.26.0`` and ``Alpine~=3.16``.
* ``django_ca.extensions.serialize_extension()`` is removed and replaced by :doc:`Pydantic serialization
  <python/pydantic>`.

Deprecation notices
===================

* This is the last release to support Python 3.8.
* The default subject format will switch from OpenSSL-style to RFC 4514 in django-ca 2.0.
* Support for OpenSSL-style subjects will be removed in django-ca 2.2.
* ``django_ca.extensions.parse_extension()`` is deprecated and should not longer be used. Use Pydantic models
  instead.

.. _changelog-1.27.0:

*******************
1.27.0 (2023-11-26)
*******************

.. NOTE::

   django-ca 1.27.0 introduced a major change in how subjects are parsed on the command-line. Please see
   :ref:`update_126_rfc4514_subjects` for migration information.

* Add support for Python 3.12 and acme 2.7.0.
* Update the Docker image to use Alpine Linux 3.18 with Python 3.12.
* Add support for passing subjects in RFC 4514 format when creating certificate authorities and certificates
  via the ``--subject-format=rfc4514`` option. This format will become the default in django-ca 2.0.
* Support for subjects in OpenSSL-style format when creating certificate authorities and certificates is
  deprecated and will issue a warning. Support for this format will be removed in django-ca 2.2.
* :ref:`settings-ca-default-subject`, :ref:`subjects in profiles <profiles-subject>` and
  :ref:`settings-ca-default-name-order` now also support a dotted string to include arbitrary object
  identifiers.
* :ref:`settings-ca-default-name-order` can now be configured in YAML files.
* Do not implicitly sort the subject of new certificate authorities according to
  :ref:`settings-ca-default-name-order`. The user is expected to supply the correct order.
* When signing certificates via the command line, implicitly sort the subject only when the profile defines a
  subject and/or the CommonName is not given and added via the SubjectAlternativeName extension. If neither is
  the case, the user is expected to supply the correct order.

Backwards incompatible changes
==============================

* Removed support for the old ``--issuer-url``, ``--issuer-alt-name``, ``--crl-url`` and ``--ocsp-url``
  options for :command:`manage.py init_ca`, :command:`manage.py edit_ca` and :command:`manage.py import_ca` in
  favor of ``--sign-ca-issuer``, ``--sign-issuer-alternative-name``, ``--sign-crl-full-name`` and
  ``--sign-ocsp-responder``.
* Support for non-standard algorithm names in profile settings was removed.
* Drop support for ``Django~=4.1``, ``cryptography~=40``, ``acme==1.25.0`` and ``celery~=5.2``.

Deprecation notices
===================

* The default subject format will switch from OpenSSL-style to RFC 4514 in django-ca 2.0.
* Support for OpenSSL-style subjects will be removed in django-ca 2.2.
* This is the last release to support Django 3.2.
* This is the last release to support acme 2.6.0.
* This is the last release to support Alpine 3.16.

REST API changes
================

.. NOTE:: The :doc:`rest_api` is still experimental and endpoints will change without notice.

* Certificate issuance is now asynchronous, similar to how certificates are issued via ACME. This enables
  using CAs where the private key is not directly available to the web server.
* The REST API must now be enabled explicitly for each certificate authority. This can be done via the admin
  interface or the ``--enable-api`` flag for :command:`manage.py init_ca`, :command:`manage.py edit_ca` and
  :command:`manage.py import_ca`.

.. _changelog-1.26.0:

*******************
1.26.0 (2023-08-26)
*******************

* Add experimental support for a :doc:`REST API <rest_api>` (fixes `issue 107
  <https://github.com/mathiasertl/django-ca/issues/107>`_).
* Add support for configuring certificate authorities to automatically include a Certificate Policy extension
  when signing certificates.
* Add support for configuring how long automatically generated OCSP responder certificates are valid.
* Add support for configuring how long OCSP responses of the automatically configured OCSP responder will be
  valid (fixes `issue 102 <https://github.com/mathiasertl/django-ca/issues/102>`_).
* The web interface now allows creating certificates with arbitrary or even empty subjects (fixes `issue 77
  <https://github.com/mathiasertl/django-ca/issues/77>`_).
* The certificate subject is now displayed as a unambiguous list instead of a string. The issuer is now also
  shown in the same way.
* Fix NGINX configuration updates when using Docker Compose. The previous setup did not update configuration
  on update if parts of it changed.
* Fix ``POSTGRES_`` configuration environment variables when using the default PostgreSQL backend. It
  previously only worked for an old, outdated alias name.
* The root URL path can now be configured via the :ref:`CA_URL_PATH <settings-ca-url-path>` setting. This
  allows you to use shorter URLs (that is, without the ``django_ca/`` prefix).
* The admin interface can now be disabled by setting the new :ref:`ENABLE_ADMIN <settings-enable-admin>`
  setting to ``False``.

Backwards incompatible changes
==============================

* Drop support for cryptography 37 and cryptography 39, acme 2.4.0 and celery 5.1.
* Passing ``ECC`` and ``EdDSA`` as key types (e.g when using :command:`manage.py init_ca`) was removed. Use
  ``EC`` and ``Ed25519`` instead. The old names where deprecated since 1.23.0.
* Removed support for the old ``--pathlen`` and ``--no-pathlen`` options for :command:`manage.py init_ca` in
  favor of ``--path-length`` and ``-no-path-length``. The old options where deprecated since 1.24.0.
* Using comma-separated lists for the ``--key-usage``, ``--extended-key-usage`` and ``--tls-feature``
  command-line options was removed. The old format was deprecated since 1.24.0.
* Remove support for `HTTP Public Key Pinning <https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning>`_, as it
  is obsolete.

Deprecation notices
===================

* This is the last release to support Django 4.1.
* This is the last release to support cryptography 40.
* This is the last release to support acme 2.5.0.
* This is the last release to support celery 5.2.

.. _changelog-1.25.0:

*******************
1.25.0 (2023-06-17)
*******************

* Add support for cryptography 41, acme 2.6.0 and celery 5.3.
* Update the Docker image to use Alpine Linux 3.18.
* Add support for adding the Certificate Policy and Issuer Alternative Name extensions when creating
  certificate authorities or end-entity certificates via the command-line.
* Add support for adding the Extended Key Usage, Issuer Alternative Name and Subject Alternative Name
  extensions when creating certificate authorities.
* Add support for overriding the Authority Information Access, CRL Distribution Points and OCSP No Check
  extensions when creating end-entity certificates via the command-line.
* Add support for string formatting operations on URL paths (see :ref:`cli_cas_string_formatting`) in
  Authority Information Access and CRL Distribution Point extensions.
* Add a temporary pip extra ``psycopg3`` for using Psycopg 3. This extra will be removed once support for
  Django 3.2 is removed. Psycopg 3 will be required in the ``postgres`` extra from then on.
* Fix import parameters to :command:`manage.py import_ca`.
* Further standardizing the command-line interface, some options for :command:`manage.py init_ca` and
  :command:`manage.py edit_ca` are renamed. See the :ref:`update notes <update_124>` for more information.

Backwards incompatible changes
==============================

* Drop support for acme 2.3.0 and cryptography 38.
* The ``CA_DIGEST_ALGORITHM`` setting was removed. Use :ref:`settings-ca-default-signature-hash-algorithm`
  instead.
* The ``CA_DEFAULT_ECC_CURVE`` setting was removed. Use :ref:`settings-ca-default-elliptic-curve` instead.
* Support for non-standard algorithm names for the ``--algorithm`` argument was removed.
* Support for non-standard elliptic curve names via the ``--elliptic-curve`` argument was removed.
* Support for custom signature hash algorithms in CRLs was removed. The algorithm used for signing the
  certificate authority is now always used.
* The old alias ``--ecc-curve`` for ``--elliptic-curve`` was removed.


Deprecation notices
===================

* This is the last release to support cryptography 37 and cryptography 39.
* This is the last release to support acme 2.4.0.
* This is the last release to support celery 5.1.
* Support for non-standard algorithm names in profile settings will be removed in django-ca 1.27.0.
* Several options :command:`manage.py init_ca` and :command:`manage.py edit_ca` are renamed, old options
  will be removed in django-ca 1.27.0. See the :ref:`update notes <update_124>` for more information.

.. _changelog-1.24.0:

*******************
1.24.0 (2023-05-01)
*******************

.. WARNING::

   **docker or source users that do *not* use PostgreSQL:**

   The `USE_TZ <https://docs.djangoproject.com/en/4.2/ref/settings/#std-setting-USE_TZ>`_ setting was
   switched to ``True`` in the Django project. See :ref:`switch-use-tz` for update information.

* Add support for cryptography 40.0, django 4.2 and acme 2.4.0 and 2.5.0.
* Use Django's timezone support by default by enabling ``USE_TZ=True``. See :ref:`switch-use-tz` for update
  information.
* Make the default order of subjects configurable via :ref:`settings-ca-default-name-order`.
* Certificates for OCSP responders now include the "OCSPNoCheck" extension by default.
* Certificates for OCSP responders now use a commonName designating the certificate as OCSP responder as
  subject, other fields from the CAs subject are discarded.
* A profile can now ignore :ref:`settings-ca-default-subject` by setting ``subject`` to ``False``.
* Copy all extensions when using :command:`manage.py resign_cert`.
* Add support for multiple OCSP responder and CA Issuer entries when creating a certificate authority.
* Add typehints when installing as wheel.

Command-line interface
======================

Continuing the standardization effort started in 1.23.0, some options have been replaced and/or use a
different syntax. See the :ref:`update notes <cli-1.24.0-updates>` for more detailed instructions.

* The ``--pathlen`` and ``--no-pathlen`` parameters for :command:`manage.py init_ca` were renamed to
  ``--path-length`` and ``--no-path-length``.
* The ``--key-usage`` option was changed to/split into ``--key-usage`` and ``--key-usage-non-critical``.
  ``--key-usage`` takes multiple option values instead of a single comma-separated list.
* The ``--ext-key-usage`` option was changed to/split into ``--extended-key-usage`` and
  ``--extended-key-usage-critical``. ``--extended-key-usage`` takes multiple option values instead of a single
  comma-separated list.
* The ``--tls-feature`` option was changed to/split into ``--tls-feature`` and ``--tls-feature-critical``.
  ``--tls-feature`` takes multiple option values instead of a single comma-separated list.
* Add support for specifying a custom Key Usage extension when using :command:`manage.py init_ca`.
* Add support for adding the Inhibit :spelling:word:`anyPolicy`, Policy Constraints and TLS feature extensions
  when using :command:`manage.py init_ca`.
* Add support for adding the OCSP No Check extension in when issuing certificates with :command:`manage.py
  sign_cert` or :command:`manage.py resign_cert`.
* Add support for specifying a date when the certificate was compromised when revoking a certificate with
  :command:`manage.py revoke_cert`.

Backwards incompatible changes
==============================

* The ``--ext-key-usage`` flag to :command:`manage.py sign_cert` was replaced with ``--extended-key-usage``.
* The critical flag for the Key Usage, Extended Key Usage and TLS Feature is now set with dedicated options,
  with the recommended value being the default. See above and the :ref:`update notes <cli-1.24.0-updates>` for
  details.
* The ``pre_issue_cert`` was removed. Use the :py:class:`~django_ca.signals.pre_sign_cert` signal instead.

Deprecation notices
===================

Removed in ``django-ca==1.25.0``:

* This is the last release to support acme 2.3.0 and cryptography 38.
* Support for the ``CA_DIGEST_ALGORITHM`` setting, use ``CA_DEFAULT_SIGNATURE_HASH_ALGORITHM`` instead.
* Support for the ``CA_DEFAULT_ECC_CURVE`` setting, use ``CA_DEFAULT_ELLIPTIC_CURVE`` instead.
* Support for non-standard algorithm names (e.g. ``sha512``, use ``SHA-512`` instead).
* Support for non-standard elliptic key curve names (e.g. ``SECP384R1``, use ``secp384r1`` instead).

Removed in ``django-ca==1.26.0``:

* Support for ``cryptography==39`` and ``acme==2.4.0`` (other versions may removed depending on release time).
* Support for using ``ECC`` and ``EdDSA`` as key type. Use ``EC`` and ``Ed25519`` instead.
* The ``--pathlen`` and ``--no-pathlen`` parameters to :command:`manage.py init_ca` will be removed. Use
  ``--path-length`` and ``--no-path-length`` instead.
* Support for comma-separated lists in ``--key-usage``, ``--extended-key-usage`` and ``--tls-feature``.
  Use lists instead (e.g. ``--key-usage keyAgreement keyEncipherment`` instead of
  ``--key usagekeyAgreement,keyEncipherment``.
* Support for non-standard TLS feature names "OCSPMustStaple" and "MultipleCertStatusRequest". Use
  ``status_request`` and ``status_request_v2`` instead.


.. _changelog-1.23.0:

*******************
1.23.0 (2023-02-18)
*******************

* Add support for cryptography 39.0.
* Add support for acme 2.2.0 and 2.3.0.
* Add support for Ed448 and Ed25519 based certificate authorities.
* Enable ACMEv2 support by default. ACMEv2 still needs to be enabled for every CA individually.
* The profile used when issuing certificates via ACMEv2 is now configurable by certificate authority. The
  default is the profile named in :ref:`settings-ca-default-profile` instead of the "server" profile.
* The ``CA_DIGEST_ALGORITHM`` setting is now called :ref:`settings-ca-default-signature-hash-algorithm`.
  Values must be a hash algorithm listed in :py:attr:`~django_ca.typehints.HashAlgorithms`.
* The default hash algorithm for certificate authorities with a DSA private key can now be configured using
  :ref:`settings-ca-default-dsa-signature-hash-algorithm`.
* The :ref:`settings-ca-crl-profiles` setting allows setting overriding parameters for automatically generated
  CRLs. This is not a new feature, but it is now documented.
* Use ``yaml.safe_load`` to load configuration files to protect against malicious configuration.
* OCSP keys now use the same signature hash algorithm as their certificate authority by default.
* CRLs are now signed with the same signature hash algorithm as their certificate authority by default.

Standardization
===============

A larger effort has been taken to use standard names for various parts of django-ca. Old option values are
supported for a few more releases, please refer to the deprecation notices below for how long they will be
supported.

* Elliptic Curve keys are now consistently referred to as "EC" instead of "ECC" and Ed25519 keys are now
  referred to as "Ed25519" instead of "EdDSA". This affects the ``--key-type`` parameter of
  :command:`manage.py init_ca` and other commands that generate private keys.
* The ``CA_DEFAULT_ECC_CURVE`` setting was renamed to ``CA_DEFAULT_ELLIPTIC_CURVE``.
* Hash algorithms are now referred to by their standard name, e.g. "SHA-512" instead of
  ":spelling:ignore:`sha512`". Please see :py:attr:`~django_ca.typehints.HashAlgorithms` for all supported
  algorithm names.

Bugfixes
========

* Fixed timestamps in CRLs if ``USE_TZ=False``. Previously, the local time as UTC was used, so freshly issued
  CRLs might not yet be valid depending on your systems timezone.
* Fixed the hash algorithm in OCSP responses. The same algorithm as in the request is now used, previously
  SHA1 was used (which happens to match the default algorithm used by OpenSSL). Some clients (e.g.
  :manpage:`openssl ocsp(1SSL)`) cannot determine the status of a certificate if a different hash is used.

Deprecation notices
===================

* This is the last release to support ``acme==2.1.0`` and ``acme==2.2.0``.
* Support for the ``CA_DIGEST_ALGORITHM`` setting will be removed in ``django-ca==1.25.0``. Use the
  :ref:`settings-ca-default-signature-hash-algorithm` setting instead.
* Support for the  ``CA_DEFAULT_ECC_CURVE`` setting will be removed in ``django-ca==1.25.0``. Use the
  :ref:`settings-ca-default-elliptic-curve` setting instead.
* Support for using ``ECC`` as key type will be removed ``django-ca==1.26.0``. Use ``EC`` instead.
* Support for using ``EdDSA`` as key type will be removed in ``django-ca==1.26.0``. Use ``Ed25519`` instead.
* Support for non-standard hash algorithm names (e.g. ``sha512`` instead of ``SHA-512`` will be removed in
  ``django-ca==1.25.0``. Use standard hash algorithm names instead (see
  :py:attr:`~django_ca.typehints.HashAlgorithms` for supported algorithms).
* Support for non-standard elliptic curve names (e.g. ``SECP256R1`` instead of ``secp256r1`` will be removed
  in ``django-ca==1.25.0``. Use standard elliptic curve names instead (see
  :py:attr:`~django_ca.constants.ELLIPTIC_CURVE_TYPES` for supported curves).
* The ``pre_issue_cert`` is will be removed in ``django_ca==1.24.0``. Use the new
  :py:class:`~django_ca.signals.pre_sign_cert` signal instead.
* The subject wrapper class ``django_ca.subject.Subject`` is will be removed in ``django-ca==1.24.0``.
* Extension wrapper classes in ``django_ca.extensions`` are will be removed in ``django_ca==1.24.0``.

Backwards incompatible changes
==============================

* Drop support for Python 3.7.
* Drop support for Django 4.0.
* Drop support for cryptography 36.0.
* Drop support for acme 1.27.0, 1.28.0 and 1.29.0, 1.30.0, 1.31.0 and 2.0.0.
* Drop support for Alpine 3.14 and 3.15.
* Remove the ``acme`` extra.
* :ref:`CA_DEFAULT_SUBJECT <settings-ca-default-subject>` must no longer be a dict. Use a list or tuple
  instead.

.. _changelog-1.22.0:

*******************
1.22.0 (2022-12-11)
*******************

.. WARNING::

   **docker-compose users:**

   * Update from 1.20 or earlier? See :ref:`the update notes <update_121-docker-compose>` to switch to named
     volumes.

* Add support for Python 3.11, Alpine 3.17, Django 4.1, cryptography 38.0 and acme 2.0.
* Support for MD5 and SHA1 hashes is removed, as they are no longer supported in upcoming releases of
  cryptography.
* New signals :py:class:`~django_ca.signals.pre_sign_cert` and :py:class:`~django_ca.signals.post_sign_cert`
  that receive the values as passed to the cryptography library.
* Add the ability to force inclusion/exclusion of the IssuingDistributionPoint extension in CRLs.
* Ensure that CRLs are regenerated periodically before the cache expires.
* Switch to the Django's `built in Redis cache <https://docs.djangoproject.com/en/4.1/topics/cache/#redis>`_
  in the docker compose setup.

Admin interface
===============

* Almost all extensions used in end entity certificates can now be modified when creating new certificates.
  The following additional extensions are now modifiable: Authority Information Access, CRL Distribution
  Points, Freshest CRL, Issuer Alternative Name, OCSP No Check and TLS Feature.

  **Limitations:**

  * The CRL Distribution Points and Freshest CRL extensions can only modify the first distribution point. If
    the selected profile defines more then one distribution point, they are added after the one from the admin
    interface.
  * The Certificate Policies extension cannot yet be modified. If the selected profile defines this extension,
    it is still added to the certificate.

* Initial values for the Authority Information Access, CRL Distribution Points and Issuer Alternative Name
  extensions are set based on information from the default certificate authority. Values may be masked by the
  default profile.
* Selecting a certificate authority will automatically update the Authority Information Access, CRL
  Distribution Points and Issuer Alternative Name extensions based on the configuration.
* Because the the user can now modify the extensions directly, the ``add_*`` directives for a profile now have
  no effect when issuing a certificate through the admin interface.

ACMEv2 support
==============

* Handle clients that do not send the ``termsOfService`` field during registration.
* Improve error handling when the CSR cannot be parsed.
* An ACME account is now considered usable if it never agreed to the terms of service *and* the certificate
  authority does not define any terms of service. Certain versions of certbot (at least version 1.31.0) never
  ask the user to agree to the terms of service if there are none to agree to.
* Allow clients to agree to the terms of service when updating the account.

Minor changes
=============

* The Docker image is now based on ``python:3.11-alpine3.17``.
* Access Descriptions in the Authority Information Access extension will now always order OCSP URLs before CA
  Issuers, inverting the previous behavior. The order of values does not matter in practice.

Backwards incompatible changes
==============================

* The docker-compose setup requires at least docker-compose 1.27.0.
* The docker-compose setup now uses Redis 7.
* Drop support for cryptography 35.0.
* Drop support for acme 1.23, 1.24, 1.25 and 1.26.
* Drop support for Celery 5.0.
* Require django-object-actions 4.0 or higher.
* Remove the ``--ca-crl`` parameter in ``manage.py dump_crl`` (this was a left
  over and has been marked as deprecated since 1.12.0).
* Drop ``django-redis-cache`` from the ``redis`` extra, as the project is abandoned. Please switch to the
  `built in redis cache <https://docs.djangoproject.com/en/4.1/topics/cache/#redis>`_ instead. If you still
  use Django 3.2, please manually install the backend.
* ``ExtendedKeyUsageOID.KERBEROS_CONSTRAINED_DELEGATION`` was removed, use the identical
  ``ExtendedKeyUsageOID.KERBEROS_PKINIT_KDC`` instead.

Deprecation notices
===================

* This is the last release to support for Python 3.7.
* This is the last release to support Django 4.0.
* This is the last release to support cryptography 36.0.
* This is the last release to support acme 1.27.0, 1.28.0 and 1.29.0, 1.30.0, 1.31.0 and 2.0.0.
* This is the last release to support Alpine 3.14 and 3.15.
* The ``acme`` extra will be removed in in the next release.
* The ``pre_issue_cert`` is deprecated and will be removed in ``django_ca==1.24.0``. Use the new
  :py:class:`~django_ca.signals.pre_sign_cert` signal instead.
* The subject wrapper class ``django_ca.subject.Subject`` is deprecated and will be removed in
  ``django-ca==1.24.0``.
* Extension wrapper classes in ``django_ca.extensions`` are deprecated and will be removed in
  ``django_ca==1.24.0``.

.. _changelog-1.21.0:

*******************
1.21.0 (2022-05-29)
*******************

.. WARNING::

   **docker-compose users:**

   * Update from 1.18 or earlier? See :ref:`the update notes <update_119>` or you might loose private keys!
   * Update from 1.20 or earlier? See :ref:`the update notes <update_121-docker-compose>` to switch to named
     volumes.

* Add support for cryptography 37.0 and Alpine Linux 3.16.
* Fix issuing certificates with multiple SubjectAlternativeNames (fixes `issue 86
  <https://github.com/mathiasertl/django-ca/issues/86>`_).
* Fix overriding the default certificate expiry in profiles (fixes `issue 87
  <https://github.com/mathiasertl/django-ca/issues/87>`_).
* Dependencies for ACMEv2 are now non-optional and the ``acme`` extra is now empty (and will be removed in
  ``django-ca==1.23.0``).
* Implement certificate revocation via ACMEv2.
* The :ref:`CA_DEFAULT_SUBJECT <settings-ca-default-subject>` setting should now be a tuple, not a
  dict. Support for using a ``dict`` will be removed in ``django-ca==1.23.0``.
* Add deployment checks (and document them in the quickstart guides) for configurations that don't use a
  shared cache subsystem (see also: `issue 85 <https://github.com/mathiasertl/django-ca/issues/85>`_).
* Fix generation of the SECRET_KEY setting when using docker and docker-compose.
* Document supported environment variables and improve general settings configuration in :doc:`settings`.
* Switch to named volumes in the docker-compose setup. Please see :ref:`update_121` for update instructions.
* Stop testing individual versions of `idna <https://pypi.org/project/idna/>`_. django-ca uses a minimal
  subset of basic functions that are unlikely to break.

Backwards incompatible changes
==============================

* Drop support for Django 2.2.
* Drop support for cryptography 3.3 and 3.4.
* Drop support for Alpine 3.12 and 3.13.

Deprecation notices
===================

* The ``acme`` extra will be removed in ``django-ca==1.23.0``.
* Support for using a dict for the :ref:`CA_DEFAULT_SUBJECT <settings-ca-default-subject>` setting will be
  removed in ``django-ca==1.23.0``.
* This is the last release to support cryptography 35.0.
* This is the last release to support Celery 5.0 (5.1+ is of course still supported).
* This is the last release to support acme 1.23, 1.24, 1.25 and 1.26.

.. _changelog-1.20.1:

*******************
1.20.1 (2022-01-29)
*******************

.. WARNING::

   **docker-compose users:** Update from 1.18 or earlier? See :ref:`the update notes <update_119>` or you
   might loose private keys!

This is a pseudo-release to add the docker-compose file for the 1.20.0 release, which was missing in said
release. There are no code changes otherwise. Thus no release artifacts (wheels, docker images etc) where
produced for this release.

* Add docker-compose file missing from the 1.20.0 release.
* Switch the default branch on GitHub to ``main``.

.. _changelog-1.20.0:

*******************
1.20.0 (2022-01-26)
*******************

.. WARNING::

   **docker-compose users:** Update from 1.18 or earlier? See :ref:`the update notes <update_119>` or you
   might loose private keys!

* Parsing and formatting of names now correctly escapes or quotes special characters.
* ``django_ca.utils.shlex_split()`` was renamed to :py:func:`~django_ca.utils.split_str`. The old name will be
  removed in ``django_ca==1.22``.
* Require a CommonName when generating a CA instead of implicitly setting the human-readable name if no
  CommonName was given.
* Add support for cryptography 36.0.0.
* Add support for Alpine 3.15.
* Make log level and message format more easily configurable with :ref:`LOG_LEVEL <settings-log-level>`,
  :ref:`LIBRARY_LOG_LEVEL <settings-library-log-level>` and :ref:`LOG_FORMAT <settings-log-format>`.
* Drop ``pytz`` as dependency (and use :py:class:`python:datetime.timezone` directly).
* Add mdlDS and mdlJWS X509 extensions for support
  `mobile Driver Licence <https://en.wikipedia.org/wiki/Mobile_driver%27s_license>`_.
* Reworked :doc:`installation instructions <install>` to link to a set of quickstart guides dedicated to each
  installation option.
* Add ``--bundle`` option to ``manage.py sign_cert`` to allow writing the whole certificate bundle.

ACMEv2 support
==============

ACMEv2 support will be included and enabled by default starting with ``django-ca==1.22``. You will still have
to enable the ACMEv2 interface for each CA that should provide one. The documentation has been updated to
assume that you want to enable ACMEv2 support.

* Add support for updating an accounts email address.
* Add support for deactivating ACME accounts.
* Fix issuing certificates if ``settings.USE_TZ=True`` (fixes `issue 82
  <https://github.com/mathiasertl/django-ca/issues/82>`_).
* Fix issuing certificates for root CAs (fixes `issue 83
  <https://github.com/mathiasertl/django-ca/issues/83>`).

Docker and docker-compose
=========================

* Update Docker image to be based on Alpine 3.15.
* Update to PostgreSQL 14 when using docker-compose.
* Do not expose ports of internal daemons when using docker-compose.

Backwards incompatible changes
==============================

* Drop support for Python 3.6.
* Drop support for Django 3.1.
* Drop support for idna 2.8, 3.0 and 3.1.
* Removed the ``manage.py dump_ocsp_index`` command.
* Remove the ``--csr-format`` parameter to ``manage.py sign_cert`` (deprecated since 1.18.0).
* ``django_ca.utils.parse_csr()`` has been removed (deprecated since 1.18.0).


Deprecation notices
===================

* This is the last release to support Django 2.2.
* This is the last release to support cryptography 3.3 and 3.4.
* This is the last release to support Alpine 3.12 and 3.13.

.. _changelog-1.19.1:

*******************
1.19.1 (2021-12-19)
*******************

* Fix "missing" migration in when using django-ca as a standalone app (fixes `issue 79
  <https://github.com/mathiasertl/django-ca/issues/79>`_).
* Add support for cryptography 36.0 and Django 4.0.

.. _changelog-1.19.0:

*******************
1.19.0 (2021-10-09)
*******************

.. WARNING::

   **docker-compose users:** See :ref:`the update notes <update_119>` or you might loose private keys!

* Implement DNS-01 validation for ACMEv2. Note that ACMEv2 support is still experimental and disabled by
  default.
* Support rendering distinguished names with any NameOID known to cryptography.
* Support creating certificates with a subject containing a ``dnQualifier``, ``PC``, ``DC``, ``title``,
  ``uid`` and ``serialNumber``.
* Only fetch expected number of bytes when validating ACME challenges via HTTP to prevent DOS attacks.
* Ensure that a certificates ``issuer`` always matches the ``subject`` from the CA that signed it.
* Fix ``manage.py regenerate_ocsp_key`` with celery enabled.
* Fix parsing of ASN.1 OtherNames from the command line. Previously, ``UTF8`` strings where not DER encoded.
* Fix ACMEv2 paths in NGINX configuration included in Docker images.
* Include a healthcheck script for uWSGI in the Docker image. Because the image is also shared for the
  Celery worker, it is not enabled by default, but the docker-compose configuration enables it.
* Add support for creating certificates with Boolean, Null, Integer, UniversalString, IA5String,
  GeneralizedTime and UTCTime values in the format described in :manpage:`ASN1_GENERATE_NCONF(3SSL)`.
* Preliminary support for OpenSSH CAs via ``EdDSA`` keys.
* The Docker image is now based on ``python:3.10-alpine3.14``.
* Add support for Python 3.10.
* Add support for cryptography 35.0.0.
* Add support for idna 3.0, 3.1 and 3.2.

Backwards incompatible changes
==============================

* Drop support for cryptography 3.0, 3.1 and 3.2.
* Remove support for configuring absolute paths for manually configured :py:class:`django_ca.views.OCSPView`.
  This functionality was officially supposed to be removed in django-ca 1.14.0.

Minor non-functional changes
============================

* The whole source code is now type hinted.
* Consistently use f-strings for faster string formatting.
* Documentation is now always generated in nitpicky mode and with warnings turned into errors.
* Remove the now redundant ``html-check`` target for documentation generation.

Deprecation notices
===================

* This is the last release to support Python 3.6.
* This is the last release to support Django 3.1.
* This is the last release to support ``idna<=3.1``.
* The ``issuer_name`` field in a profile is deprecated and no longer has any effect. The parameter will be
  removed in django-ca 1.22.

.. _changelog-1.18.0:

*******************
1.18.0 (2021-05-15)
*******************

* Add support for Django 3.2.
* Prevent auto-completion of the CA password field in the admin interface.
* Improve CSR validation when using the admin interface.
* Check permissions when resigning certificates.
* Require the ``change certificate`` permission when revoking certificates.
* Preselect profile of original certificate when resigning certificates.
* Make sure that operators for OrderedSetExtension always return an instance of the implementing class, not of
  the base class.
* Certificate bundles now always end with a newline, as normal bundles do.
* Add setuptools extras for ``mysql`` and ``postgres``.
* Add MySQL support for the Docker image.

Backwards incompatible changes
==============================

* Don't load configuration from ``localsettings.py`` (deprecated since ``1.15.0``).
* The ``x509`` property and ``dump_certificate()`` where removed from
  :py:class:`~django_ca.models.CertificateAuthority` and :py:class:`~django_ca.models.Certificate`:

  * To access a string-encoded PEM use ``obj.pub.pem`` (was: ``obj.x509``).
  * To update an instance with a certificate use :py:func:`~django_ca.models.X509CertMixin.update_certificate`
    (was: ``obj.x509 = ...``).
  * Use ``obj.pub.pem`` or ``obj.pub.der`` to get an encoded certificate (was: ``obj.dump_certificate()``).

* Drop support for Django 3.0.
* Drop support for cryptography 2.8 and 2.9.
* Drop support for Celery 4.3 and 4.4.
* Drop support for idna 2.9.

Python API
==========

* Store certificates and CSRs as bytes to improve access speed.

Linting and continuous integration
==================================

* Use `GitHub Actions <https://github.com/features/actions>`_ instead of Travis.
* Use :file:`pyproject.toml` for all tools that support it.
* Code is now formatted with `black <https://github.com/psf/black>`_.
* Code is now linted using `pylint <https://www.pylint.org/>`_.
* Code is now fully type-hinted and type safe according to `mypy <https://mypy.readthedocs.io/>`_. This
  requires the upcoming release of cryptography (current: 3.4).
* Documentation is now cleaned with `doc8 <https://github.com/PyCQA/doc8>`_.
* Documentation is now spell-checked using `sphinxcontrib.spelling
  <https://sphinxcontrib-spelling.readthedocs.io/en/latest/index.html>`_.

Deprecation notices
===================

* This is the last release to support cryptography 3.0, 3.1 and 3.2.
* Passing a ``str`` or ``bytes`` to :py:func:`~django_ca.managers.CertificateManager.create_cert` will be
  removed in django-ca 1.20.0.
* Passing a ``str`` as an algorithm in :py:func:`~django_ca.models.CertificateAuthority.get_crl`,
  :py:func:`~django_ca.profiles.Profile.create_cert` is deprecated and will no longer work in django-ca
  1.20.0. Pass a :py:class:`~cg:cryptography.hazmat.primitives.hashes.HashAlgorithm` instance instead.
* ``django_ca.utils.parse_csr()`` is no longer useful and will be removed in django-ca 1.20.0.
* Creating an index for running an OCSP responder with :manpage:`openssl-ocsp(1SSL)` is deprecated and will be
  removed in django-ca 1.20.0. The man page explicitly states it "is only useful for test and demonstration
  purposes", and we can solidly run our own responders by now.

.. _changelog-1.17.3:

*******************
1.17.3 (2021-03-14)
*******************

* Use Alpine 3.13 and Python 3.9 in the Docker image.
* Include templates in installations via pip (fixes `issue 72
  <https://github.com/mathiasertl/django-ca/issues/72>`_)

.. _changelog-1.17.2:

*******************
1.17.2 (2021-02-19)
*******************

* Update for compatibility with cryptography 3.4.
* Add support for Alpine 3.13.
* Due to cryptography requiring a relatively new version of Rust, support for Alpine<3.12 is dropped.

.. _changelog-1.17.1:

*******************
1.17.1 (2021-01-12)
*******************

* Bugfix release for 1.17.0 to address packaging issues for wheels (when installed with ``pip install``).
* Include acme submodule (fixes `issue 67 <https://github.com/mathiasertl/django-ca/issues/67>`_).
* Relax dependencies for josepy (fixes `issue 68 <https://github.com/mathiasertl/django-ca/issues/68>`_).
* Add tests in :file:`Dockerfile` to make sure that these issues cannot happen again.

.. _changelog-1.17.0:

*******************
1.17.0 (2020-12-30)
*******************

* New :ref:`CA_DEFAULT_CA <settings-ca-default-ca>` setting to consistently configure the CA used by default.
* Fix the ``--issuer-alt-name`` option for :command:`manage.py init_ca` and :command:`manage.py edit_ca`.
* Correctly handle IDNA domain names in URLs and certificates.
* **Preliminary** :doc:`acme` (disabled by default).
* CAs have new fields ``caa_identity``, ``website`` and ``terms_of_service``, which are used by ACME.
* Add support for Python 3.9.
* Add support for cryptography 3.1, 3.2 and 3.3.
* Start linting code with `pylint <https://www.pylint.org/>`_.
* Secure CSRF and session cookies using Django's ``SESSION_COOKIE_SECURE``, ``CSRF_COOKIE_HTTPONLY`` and
  ``CSRF_COOKIE_SECURE`` settings.

Docker (Compose)
================

* Add thorough :doc:`quickstart_docker_compose`.
* Collect static files on startup instead of during build. The latter causes problems with image updates.
* Make :command:`manage.py` available as the ``manage`` shortcut.
* Add several security related headers to the admin interface (CSP, etc).
* Include a template for a complete TLS configuration.

Backwards incompatible changes
==============================

* Drop support for Python 3.5.
* Drop support for cryptography 2.7.
* Drop support for Celery 4.2.
* Drop support for idna 2.8.

Deprecation notices
===================

* This is the last release to support Celery 4.3 and 4.4.
* This is the last release to support cryptography 2.8 and 2.9.
* This is the last release to support Django 3.0 (2.2 LTS will still be supported).
* This is the last release to support idna 2.9.
* This is the last release to support Alpine 3.10.

.. _changelog-1.16.1:

*******************
1.16.1 (2020-09-06)
*******************

* This is a bugfix release for 1.16.0 that mostly addresses CRL validation issues.
* Add support for cryptography 3.1.
* Fix OCSP, Issuer and CRL URLs for intermediate CAs that are not a *direct* child of a root CA.
* Fix AuthorityKeyIdentifier in CRLs for intermediate CAs
  (`issue 65 <https://github.com/mathiasertl/django-ca/issues/65>`_).
* Properly handle CommonNames which are not parsable as SubjectAlternativeName in admin interface
  (`issue 62 <https://github.com/mathiasertl/django-ca/issues/62>`_).
* Minor documentation updates (`issue 63 <https://github.com/mathiasertl/django-ca/issues/63>`_).
* Fix error in :command:`manage.py notify_expiring_certs` in non-timezone aware setups.
* Override terminal size when running test cases, otherwise the output of argparse depends on the
  terminal size, leading to test failures on large terminals.

.. _changelog-1.16.0:

*******************
1.16.0 (2020-08-15)
*******************

* Add support for cryptography 2.9 and 3.0.
* Add support for Django 3.1.
* The Docker image is now based on Alpine Linux 3.12.
* Update `redis` to version 6 and NGINX version 18 when using docker-compose
* Finally update Sphinx since `numpydoc#215 <https://github.com/numpy/numpydoc/issues/215#event-3371204027>`_
  is finally fixed.
* The profile used to generate the certificate is now stored in the database.
* It is no longer optional to select a profile in the admin interface when creating a certificate.
* Certificates have a new ``autogenerated`` boolean flag, which is ``True`` for automatically generated OCSP
  certificates.
* The admin interface will list only valid certificates and filter autogenerated certificates by default.

Backwards incompatible changes
==============================

* Drop support for Django 1.11 and 2.1.
* Drop support for Celery 4.0 and 4.1.
* Drop support for OpenSSL 1.1.0f and earlier. This affects Debian oldoldstable (Jessie), Ubuntu 16.04 and
  Alpine 3.8.
* ``Certificate.objects.init()`` and ``profiles.get_cert_profile_kwargs()`` were removed. Use
  :py:func:`Certificate.objects.create_cert() <django_ca.managers.CertificateManager.create_cert>` instead.

Deprecation notices
===================

* This is the last release to support Python 3.5.
* This is the last release to support cryptography 2.7.
* This is the last release to support Celery 4.2.
* This is the last release to support idna 2.8.
* The Django project included in this git repository will stop loading ``localsetttings.py`` files in
  ``django-ca>=1.18.0``.
* The format for the ``CA_PROFILES`` setting has changed in :ref:`1.14.0 <changelog-1.14.0>`. Support for the
  old format will be removed in ``django-ca==1.17.0``. Please see previous versions for migrations
  instructions.

.. _changelog-1.15.0:

*******************
1.15.0 (2020-01-11)
*******************

* Add support for Django 3.0.
* The Docker image is now based on Alpine Linux 3.11.
* The default project now supports configuring django-ca using YAML configuration files. Configuration using
  ``localsettings.py`` is now deprecated and will be removed in ``django-ca>=1.18.0``.
* Start supporting Celery tasks to allow running tasks in a distributed, asynchronous task queue. Some tasks
  will automatically be run with Celery if it is enabled. Celery is used automatically if installed, but can
  always be disabled by setting ``CA_USE_CELERY=False``.
* Drop dependency ``six`` (since we no longer support Python 2.7).
* Allow caching of CRLs via :command:`manage.py cache_crls`.
* The :command:`manage.py init_ca` command will now automatically cache CRLs and generate OCSP keys for the
  new CA.
* Support ``POSTGRES_*`` and ``MYSQL_*`` environment variables to configure database access credentials in the
  same way as the Docker images for PostgreSQL and MySQL do.
* There now are `setuptools extras
  <https://packaging.python.org/tutorials/installing-packages/#installing-setuptools-extras>`_ for ``redis``
  and ``celery``, so you can install all required dependencies at once.
* Add ``CA_PASSWORDS`` setting to allow you to set the passwords for CAs with encrypted private keys. This
  is required for automated tasks where the private key is required.
* Add ``CA_CRL_PROFILES`` setting to configure automatically generated CRLs. Note that this setting will
  likely be moved to a more general setting for automatic tasks in future releases.
* ``django_ca.extensions.AuthorityKeyIdentifier`` now also supports issuers and serials.
* :py:func:`~django_ca.utils.parse_general_name` now returns a :py:class:`~cg:cryptography.x509.GeneralName`
  unchanged, but throws an error if the name isn't a ``str`` otherwise.
* New class ``django_ca.utils.GeneralNameList`` for extensions that store a list of general names.
* Add support for the ``django_ca.extensions.FreshestCRL`` extension.
* Store CA private keys in the ``ca/`` subdirectory by default, the directory can be configured using
  ``manage.py init_ca --path=...``.

Backwards incompatible changes
==============================

* Drop support for Python 2.7.
* Drop support for cryptography 2.5 and 2.6.
* Drop support for Alpine 3.8 (because PostgreSQL and MySQL depend on LibreSSL).
* Removed the ``manage.py migrate_ca`` command. If you upgrade from before :ref:`1.12.0 <changelog-1.12.0>`,
  upgrade to :ref:`1.14.0 <changelog-1.14.0>` first and update the file storage setting.
* Removed the ``ca_crl`` setting in :py:class:`~django_ca.views.CertificateRevocationListView`, use ``scope``
  instead.

Docker
======

* Add a :ref:`docker-compose.yml <docker-compose>` file to quickly launch a complete service stack.
* Add support for Celery, MySQL, PostgreSQL and Redis.
* Change the working directory to ``/usr/src/django-ca/ca``, so :command:`manage.py` can now be invoked using
  ``python manage.py`` instead of ``python ca/manage.py``.
* Add a Celery startup script (``./celery.sh``).
* Add a NGINX configuration template at ``nginx/default.template``.
* Static files are now included in a "collected" form, so they don't have to collected on startup.
* Generate OCSP keys and cache CRLs on startup.
* Use `BuildKit <https://docs.docker.com/develop/develop-images/build_enhancements/>`__ to massively speed up
  the Docker image build.

Bugfixes
========

* Fix generation of CRLs and OCSP keys for CAs with a DSA private key.
* Fix storing an empty list of CRL URLs in some corner cases (when the function receives an empty list).
* Fix naming CAs via serial on the command line if the serial starts with a zero.
* Consistently style serials in a monospace font in admin interface.
* The ``ocsp`` profile used for OCSP keys no longer copies the CommonName (which is the same as in the CA) to
  to the SubjectAlternativeName extension. The CommonName is frequently a human-readable name in CAs.

Deprecation notices
===================

* This is the last release to support Django 1.11 and 2.1.
* The Django project included in this git repository will stop loading ``localsetttings.py`` files in
  ``django-ca>=1.18.0``.
* ``Certificate.objects.init()`` and ``get_cert_profile_kwargs()`` were deprecated in :ref:`1.14.0
  <changelog-1.14.0>` and will be removed in ``django-ca==1.16.0``. Use
  :py:func:`Certificate.objects.create_cert() <django_ca.managers.CertificateManager.create_cert>` instead.
* The format for the ``CA_PROFILES`` setting has changed in :ref:`1.14.0 <changelog-1.14.0>`. Support for the
  old format will be removed in ``django-ca==1.17.0``. Please see previous versions for migration
  instructions.

.. _changelog-1.14.0:

*******************
1.14.0 (2019-11-03)
*******************

* ``regenerate_ocsp_keys`` now has a quiet mode and only generates keys where the CA private key is available.
* Minor changes to make the release compatible with Django 3.0a1.
* Introduce a new, more flexible format for the The format of the :ref:`CA_PROFILES <settings-ca-profiles>`
  setting. The new :doc:`/profiles` page provides more information.
* New dependency: `six <https://pypi.org/project/six/>`_, since Django 3.0 no longer includes it.
* New dependency: `asn1crypto <https://pypi.org/project/asn1crypto/>`_, since cryptography no longer depends
  on it.
* Serials are now zero-padded when output so that the last element always consists of two characters.
* More consistently output serials with colons, use a monospace font in the admin interface.
* Fix profile selection in the admin interface.
* Fix display of values from CSR in the admin interface.
* Add a copy-button next to values from the CSR to enable easy copy/paste from the CSR.
* Test suite now includes Selenium tests for all JavaScript functionality.
* ``dev.py coverage`` can now output a text summary using ``--format=text``.

Backwards incompatible changes
==============================

* Drop support for cryptography 2.3 and 2.4.
* Drop support for idna 2.7.
* Extensions now always expect a dict or a cryptography extension as a value.  Anything else was unused in
  practice.
* ``django_ca.extensions.KeyUsage``, ``django_ca.extensions.ExtendedKeyUsage`` and
  ``django_ca.extensions.TLSFeature`` now behave like an ordered set and support all operators that a set
  does.
* Running an OCSP responder using ``oscrypto``/``ocspbuilder`` is no longer supported.

Extensions
==========

* ``django_ca.extensions.KeyUsage`` is now marked as critical by default.
* ``django_ca.extensions.ExtendedKeyUsage`` now supports the ``anyExtendedKeyUsage`` OID.

Deprecation notices
===================

* This is the last release to support Python 2.7.
* This is the last release to support cryptography 2.5 and 2.6.
* This is the last release to be tested with Alpine 3.7.
* This is the last release to support updating CA private keys to the filestorage API. :command:`manage.py
  migrate_ca` will be removed in the next release.
* This will be the last release to support the ``ca_crl`` setting in
  :py:class:`~django_ca.views.CertificateRevocationListView`.
* ``Certificate.objects.init()`` has been deprecated in favor of :py:func:`Certificate.objects.create_cert()
  <django_ca.managers.CertificateManager.create_cert>`.  The old method will be removed in
  ``django-ca==1.16``.
* ``get_cert_profile_kwargs()`` was only used by ``Certificate.objects.init()`` and will  thus also be removed
  in ``django-ca==1.16``.
* The old format for ``CA_PROFILES`` will be supported until ``django-ca==1.16``. Please see previous versions
  for migration instructions.

.. _changelog-1.13.0:

*******************
1.13.0 (2019-07-14)
*******************

* Add support for cryptography 2.7.
* Moved ``setup.py recreate_fixtures`` to ``recreate-fixtures.py``.
* Moved all other extra ``setup.py`` commands to ``dev.py`` to remove clutter.
* Move ``fab init_demo`` to ``dev.py init-demo``.
* Use OpenSSL instead of LibreSSL in :file:`Dockerfile` to enable testing for Alpine 3.7. The cryptography
  documentation also `suggests <https://cryptography.io/en/stable/installation/#alpine>`_ OpenSSL.
* The Fabric file has been removed.
* Remove the ``CA_PROVIDE_GENERIC_CRL`` setting, the default URL configuration now includes it.
* The Docker image is now based on Alpine Linux 3.10.
* **BACKWARDS INCOMPATIBLE:** Drop support for cryptography 2.2.
* **BACKWARDS INCOMPATIBLE:** Drop support for idna 2.6.

Deprecation Notices
===================

* This is the last release to support cryptography 2.3 and 2.4.
* This is the last release to support idna 2.7.
* This is the last release to support OCSP using ``oscrypto``/``ocspbuilder``.
* ``CertificateRevocationListView.ca_crl`` is deprecated in favor of the ``scope`` parameter. If you have set
  ``ca_crl=True`` just set ``scope="ca"`` instead.
* A new more extendable format for the :ref:`CA_PROFILES <settings-ca-profiles>` setting will be introduced in
  1.14.0. As a result, extensions will no longer support instantiation from lists or strings, so avoid usage
  wherever you can.

Extensions
==========

* Implement the ``django_ca.extensions.CRLDistributionPoints`` extension and
  ``django_ca.extensions.CertificatePolicies`` extension.
* Add the ``ipsecEndSystem``, ``ipsecTunnel`` and ``ipsecUser`` extended key usage types. These are actually
  very rare and only occur in the "TrustID Server A52" CA.
* Extensions now consistently serialize to dictionaries.

Command-line interface
======================

* The ``view_ca`` command will now display the full path to the private key, if possible.
* The ``migrate_ca`` command now has a ``--dry`` parameter and has a updated help texts.
* The new ``regenerate_ocsp_keys`` command allows you to automatically generate OCSP keys that are used by the
  new default OCSP views.

Python API
==========

* Add the ``root`` property to CAs and certificates returning the root Certificate Authority.
* ``django_ca.managers.CertificateManager.sign_cert()`` now also accepts a
  :py:class:`~cg:cryptography.x509.CertificateSigningRequest` as ``csr`` value.
* Add the ``issuer_url``, ``crl_url``, ``ocsp_url`` and ``issuer_alternative_name`` parameter to
  ``django_ca.managers.CertificateManager.sign_cert()`` to allow overriding or disabling the default
  values from the CA. This can also be used to pass extensions that do not just contain the URL using the
  ``extra_extensions`` parameter.
* Add the :py:func:`~django_ca.models.CertificateAuthority.get_crl` function to get a CRL for the CA.
* Add the :py:func:`~django_ca.models.CertificateAuthority.generate_ocsp_key` function to generate OCSP keys
  that are automatically picked up by the generic OCSP views.
* Both :py:class:`~django_ca.models.CertificateAuthority` and
  :py:class:`~django_ca.models.Certificate` now have a ``root`` property pointing to the Root CA.

OCSP
====

* The :ref:`CA_DEFAULT_HOSTNAME <settings-ca-default-hostname>` setting is now used to set generic OCSP URLs
  by default.
* The ``dump_ocsp_index`` management command now excludes certificates expired for more then a day or are not
  yet valid.

CRLs
====

* Issued CRLs now confirm to `RFC 5280`_:

  * Add the `CRL Number <https://tools.ietf.org/html/rfc5280.html#section-5.2.3>`_ extension.
  * Add the `Authority Key Identifier <https://tools.ietf.org/html/rfc5280.html#section-5.2.1>`_ extension.

* Add the `Issuing Distribution Point <https://tools.ietf.org/html/rfc5280.html#section-5.2.5>`_
  extension. This extension requires that you use cryptography>=2.5.
* Add support for setting an Invalidity Date (see `RFC 5280, 5.3.2
  <https://tools.ietf.org/html/rfc5280.html#section-5.3.2>`_) for CRLs, indicating when the certificate was
  compromised.
* CRL entries will no longer include a `Reason Code <https://tools.ietf.org/html/rfc5280#section-5.3.1>`_ if
  the reason is unspecified (recommended in RFC 5280).
* Expose an API for creating CRLs via :py:func:`CertificateAuthority.get_crl()
  <django_ca.models.CertificateAuthority.get_crl>`.

.. _changelog-1.12.0:

*******************
1.12.0 (2019-04-02)
*******************

* Fix traceback when a certificate that does not exist is viewed in the admin interface.
* Add support for cryptography 2.5 and 2.6.
* Start using `Django storage backends <https://docs.djangoproject.com/en/2.1/ref/files/storage/>`_ for files
  used by django-ca. This allows you to store files on a shared storage system (e.g. one from `django-storages
  <https://django-storages.readthedocs.io/>`_) to support a redundant setup.
* Add support for ``PrecertPoison`` and ``django_ca.extensions.OCSPNoCheck`` extensions.
* Implement the ``django_ca.extensions.PrecertificateSignedCertificateTimestamps`` extension, currently can
  only be used for reading existing certificates.
* Optimize PrecertificateSignedCertificateTimestamps in Django admin view.
* Make sure that all extensions are always hashable.
* Switch Docker image to `Alpine Linux 3.9 <https://www.alpinelinux.org/posts/Alpine-3.9.0-released.html>`_.
* **BACKWARDS INCOMPATIBLE:** Drop support for Python 3.4.
* **BACKWARDS INCOMPATIBLE:** Drop support for Django 2.0.
* **BACKWARDS INCOMPATIBLE:** Drop support for cryptography 2.1.
* **DEPRECATION NOTICE:** This is the last release to support cryptography 2.2.
* **DEPRECATION NOTICE:** This is the last release to support idna 2.6.

Django File storage API
=======================

**django-ca** now uses the `File storage API <https://docs.djangoproject.com/en/2.1/ref/files/storage/>`_ to
store CA private keys as well as files configured for OCSP views. This allows you to use different storage
backends (e.g. from `django-storages <https://django-storages.readthedocs.io/>`_) to store files on a
file system shared between different servers, e.g. to provide a redundant setup.

.. NOTE::

   The switch does require some manual intervention when upgrading. The old way of storing files is still
   supported and will continue to work until version 1.14. Please see previous versions for information on how
   to upgrade.

* Use file storage API for reading/writing private keys of CAs.
* Use file storage API for reading the responder key and certificate for OCSP.
* New settings :ref:`CA_FILE_STORAGE <settings-ca-file-storage>` and :ref:`CA_FILE_STORAGE_KWARGS
  <settings-ca-file-storage-kwargs>` to configure file storage.

OCSP
====

* Re-implement OCSP using cryptography, used only if cryptography>=2.4 is installed.
* ``django_ca.views.OCSPBaseView.responder_key`` may now also be a relative path to be used with the
  Django storage system.
* ``django_ca.views.OCSPBaseView.responder_cert`` may now also be a relative path to be used with the
  Django storage system.
* ``django_ca.views.OCSPBaseView.responder_cert`` may now also be a preloaded certificate. If you still use
  ``cryptography<2.4`` use a ``oscrypto.asymmetric.Certificate``, for newer versions you must use a
  :py:class:`cg:cryptography.x509.Certificate`.
* Fix log output string interpolation issue in OCSP responder.

.. _changelog-1.11.0:

*******************
1.11.0 (2018-12-29)
*******************

* Remove colons from CA private keys (fixes `#29 <https://github.com/mathiasertl/django-ca/issues/28>`_).
* Filenames for downloading certificates are based on the CommonName (fixes
  `#53 <https://github.com/mathiasertl/django-ca/issues/53>`_).
* Fix certificate bundle order (fixes `#55 <https://github.com/mathiasertl/django-ca/issues/55>`_).
* Management commands ``dump_ca`` and ``dump_cert`` can now dump whole certificate bundles.
* New setting :ref:`CA_DEFAULT_KEY_SIZE <settings-ca-default-key-size>` to configure the default key size
  for new CAs.
* Fix display of the NameConstraints extension in the admin interface.
* Further optimize the Docker image size (~235MB -> ~140MB).

Deprecation Notices
===================

This release will be the last release to support some software versions:

* This will be the last release that supports for Python 3.4
  (see `Status of Python branches <https://devguide.python.org/#status-of-python-branches>`_).
* This will be the last release that supports for Django 2.0
  (see `Supported Versions <https://www.djangoproject.com/download/#supported-versions>`_).
* This will be the last release that supports cryptography 2.1.

Python API
==========

* **BACKWARDS INCOMPATIBLE:** Renamed the ``subjectAltName`` parameter of
  ``Certificate.objects.init()`` to ``subject_alternative_name`` to be consistent with other extensions.
* Document how to use the ``name_constraints`` parameter in
  :py:meth:`CertificateAuthority.objects.init() <django_ca.managers.CertificateAuthorityManager.init>`
* Extensions can now always be passed as ``django_ca.extensions.base.Extension`` subclass or as any
  value accepted by the constructor of the specific class.
* Add ability to add any custom additional extension using the ``extra_extensions`` parameter.
* ``django_ca.subject.Subject`` now implements every ``dict`` method.
* The ``~django_ca.signals.pre_issue_cert`` signal will now receive normalized values.
* The ``~django_ca.signals.pre_issue_cert`` signal is only invoked after all parameters are verified.
* Implement the ``django_ca.extensions.AuthorityInformationAccess``,
  ``django_ca.extensions.BasicConstraints``, ``django_ca.extensions.IssuerAlternativeName``,
  ``django_ca.extensions.SubjectAlternativeName`` and ``django_ca.extensions.NameConstraints`` extensions.

Testing
=======

* Add cryptography 2.4.2 to the test-suite.
* Add the ``setup.py docker_test`` command to test the image using various alpine-based images.
* Test for certificates that are not yet valid.
* The child CA used for testing now contains more extensions.
* Freeze time in some test cases to avoid test failures when certificates eventually expire.
* Test some documentation pages, to make sure they are actually correct.

.. _changelog-1.10.0:

*******************
1.10.0 (2018-11-03)
*******************

* New dependency: `django-object-actions <https://github.com/crccheck/django-object-actions>`_.
* Add ability to resign existing certificates.
* Management command ``list_cas`` now optionally supports a tree view.
* Use more consistent naming for extensions throughout the code and documentation.
* Renamed the ``--tls-features`` option of the ``sign_cert`` command to ``--tls-feature``, in line with the
  actual name of the extension.
* Allow the ``TLSFeature`` extension in profiles.
* Add link in the admin interface to easily download certificate bundles.
* Support ECC private keys for new Certificate Authorities.
* Store CA private keys in the more secure `PKCS8 format
  <https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/#cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8>`_.
* The Certificate change view now has a second "Revoke" button as object action next to the "History" button.

Python API
==========

* Add the :doc:`Python API <python/intro>` as a fully supported interface to **django-ca**.
* New module ``django_ca.extensions`` to allow easy and consistent handling of X509 extensions.
* Fully document various member attributes of :py:class:`~django_ca.models.CertificateAuthority` and
  :py:class:`~django_ca.models.Certificate`, as well ``django_ca.subject.Subject`` and as all new Python code.
* The parameters for functions in :py:class:`~django_ca.managers.CertificateManager` and
  :py:meth:`~django_ca.managers.CertificateAuthorityManager.init` were cleaned up for consistent naming and so
  that a user no longer needs to use classes from the cryptography library. Parameters are now optional if
  default settings exist.
* Variable names have been renamed to be more consistent to make the code more readable.

Testing
=======

* Also test with Python 3.7.0.
* Add configuration for `tox <https://tox.readthedocs.io/en/latest/>`_.
* Speed up test-suite by using :py:meth:`~django:django.test.Client.force_login` and
  `PASSWORD_HASHERS <https://docs.djangoproject.com/en/dev/topics/testing/overview/#password-hashing>`_.
* Load keys and certs in for every test case instead for every class, improving test case isolation.
* Add two certificates that include all and no extensions at all respectively to be able to test edge cases
  more consistently and thoroughly.
* Add function ``cmd_e2e`` to call :command:`manage.py` scripts in a way that arguments are passed by argparse
  as if they where called from the command-line. This allows more complete testing including parsing
  command-line arguments.
* Error on any :py:mod:`python:warnings` coming from django-ca when running the test-suite.

.. _changelog-1.9.0:

******************
1.9.0 (2018-08-25)
******************

* Allow the creation of Certificates with multiple OUs in their subject (command-line only).
* Fix issues with handling CAs with a password on the command-line.
* Fix handling of certificates with no CommonName and/or no x509 extensions.
* Add support for displaying Signed Certificate Timestamps (SCT) Lists, as described in
  `RFC 6962, section 3.3 <https://tools.ietf.org/html/rfc6962#section-3.3>`_.
* Add limited support for displaying Certificate Policies, as described in
  `RFC 5280, section 4.2.14 <https://tools.ietf.org/html/rfc5280#section-4.2.1.4>`_ and
  `RFC 3647 <https://tools.ietf.org/html/rfc3647>`_.
* Correctly display extensions with an OID unknown to django-ca or even cryptography.
* Properly escape x509 extensions to prevent any injection attacks.
* Django 2.1 is now fully supported.
* Fix example command to generate a CSR (had a stray '/').
* Run test-suite with template debugging enabled to catch silently skipped template errors.

Docker
======

* Base the :doc:`Docker image <docker>` on ``python:3-alpine`` (instead of ``python:3``), yielding a much
  smaller image (~965MB -> ~235MB).
* Run complete test-suite in a separate build stage when building the image.
* Provide ``uwsgi.ini`` for fast deployments with the uWSGI protocol.
* Add support for passing additional parameters to uWSGI using the ``DJANGO_CA_UWSGI_PARAMS`` environment
  variable.
* Create user/group with a predefined UID/GID of 9000 to allow better sharing of containers.
* Add ``/usr/share/django-ca/`` as named volume, allowing a setup where an external web server serves static
  files.
* Add documentation on how to run the container in combination with an external web server.
* Add documentation on how to run the container as a different UID/GID.

.. _changelog-1.8.0:

******************
1.8.0 (2018-07-08)
******************

* Add :doc:`Django signals </signals>` to important events to let users add custom actions (such as email
  notifications etc.) to those events (fixes `#39 <https://github.com/mathiasertl/django-ca/issues/39>`_).
* Provide a Docker container for fast deployment of **django-ca**.
* Add the :ref:`CA_CUSTOM_APPS <settings-ca-custom-apps>` setting to let users that use **django-ca** as a
  :doc:`standalone project <quickstart_from_source>` add custom apps, e.g. to register signals.
* Make the ``otherName`` extension actually usable and tested (see `PR47
  <https://github.com/mathiasertl/django-ca/pull/47>`_)
* Add the ``smartcardLogon`` and ``msKDC`` extended key usage types. They are needed for some AD and OpenLDAP
  improvements (see `PR46 <https://github.com/mathiasertl/django-ca/pull/46>`_)
* Improve compatibility with newer ``idna`` versions (``".com"`` now also throws an error).
* Drop support for Django 1.8 and Django 1.10.
* Improve support for yet-to-be-released Django 2.1.
* Fix admin view of certificates with no SubjectAlternativeName extension.

.. _changelog-1.7.0:

******************
1.7.0 (2017-12-14)
******************

* Django 2.0 is now fully supported. This release still supports Django 1.8, 1.10 and 1.11.
* Add support for the :ref:`TLSFeature <extension-tls-feature>` extension.
* Do sanity checks on the ``pathlen`` attribute when creating Certificate Authorities.
* Add sanity checks when creating CAs:

  * When creating an intermediate CA, check the ``pathlen`` attribute of the parent CA to make sure that the
    resulting CA is not invalid.
  * Refuse to add a CRL or OCSP service to root CAs. These attributes are not meaningful there.

* Massively update :doc:`documentation for the command-line interface </cli/intro>`.
* CAs can now be identified using name or serial (previously: only by serial) in
  :ref:`CA_OCSP_URLS <settings-ca-ocsp-urls>`.
* Make ``fab init_demo`` a lot more useful by signing certificates with the client CA and include CRL and OCSP
  links.
* Run ``fab init_demo`` and documentation generation through Travis-CI.
* Always display all extensions in the django admin interface.
* NameConstraints are now delimited using a ``,`` instead of a ``;``, for consistency with other parameters
  and so no bash special character is used.

Bugfixes
========

* Check for permissions when downloading certificates from the admin interface. Previously, users without
  admin interface access but without permissions to access certificates, where able to guess the URL and
  download public keys.
* Add a missing migration.
* Fix the value of the CRLDistributionPoints x509 extension when signing certificates with Python2.
* The ``Content-Type`` header of CRL responses now defaults to the correct value regardless of type (DER or
  PEM) used.
* If a wrong CA is specified in :ref:`CA_OCSP_URLS <settings-ca-ocsp-urls>`, an OCSP internal error is
  returned instead of an uncaught exception.
* Fix some edge cases for serial conversion in Python2. Some serials where converted with an "L" prefix in
  Python 2, because ``hex(0L)`` returns ``"0x0L"``.

.. _changelog-1.6.3:

******************
1.6.3 (2017-10-21)
******************

* Fix various operations when ``USE_TZ`` is ``True``.
* Email addresses are now independently validated by ``validate_email``. cryptography 2.1 no longer validates
  email addresses itself.
* Require ``cryptography>=2.1``. Older versions should not be broken, but the output changes breaking
  :py:mod:`doctests <doctest>`, meaning they're no longer tested either.
* CA keys are no longer stored with colons in their filename, fixing ``init_ca`` under Windows.

.. _changelog-1.6.2:

******************
1.6.2 (2017-07-18)
******************

* No longer require a strict cryptography version but only ``>=1.8``. The previously pinned version is
  incompatible with Python 3.5.
* Update requirements files to newest versions.
* Update imports to ``django.urls.reverse`` so they are compatible with Django 2.0 and 1.8.
* Make sure that :command:`manage.py check` exit status is not ignored for ``setup.py code_quality``.
* Conform to new sorting restrictions for ``isort``.

.. _changelog-1.6.1:

******************
1.6.1 (2017-05-05)
******************

* Fix signing of wildcard certificates (thanks `RedNixon <https://github.com/mathiasertl/django-ca/pull/25>`_).
* Add new management commands ``import_ca`` and ``import_cert`` so users can import existing CAs and
  certificates.

.. _changelog-1.6.0:

******************
1.6.0 (2017-04-21)
******************

New features and improvements
=============================

* Support CSRs in DER format when signing a certificate via :command:`manage.py sign_cert`.
* Support encrypting private keys of CAs with a password.
* Support Django 1.11.
* Allow creating CRLs of disabled CAs via :command:`manage.py dump_crl`.
* Validate DNSNames when parsing general names. This means that signing a certificate with CommonName that is
  not a valid domain name fails if it should also be added as SubjectAlternativeName extension (see
  ``--cn-in-san`` option).
* When configuring :py:class:`~django_ca.views.OCSPView`, the responder key and certificate are verified
  during configuration. An erroneous configuration thus throws an error on startup, not during runtime.
* The test suite now tests certificate signatures itself via ``pyOpenSSL``,  so an independent library is used
  for verification.

Bugfixes
========

* Fix the ``authorityKeyIdentifier`` extension when signing certificates with an intermediate CA.
* Fix creation of intermediate CAs.

.. _changelog-1.5.1:

******************
1.5.1 (2017-03-07)
******************

* Increase minimum field length of serial and common name fields.
* Tests now call full_clean() for created models. SQLite (which is used for testing) does not enforce the
  ``max_length`` parameter.

.. _changelog-1.5.0:

******************
1.5.0 (2017-03-05)
******************

* Completely remove pyOpenSSL and consistently use `cryptography <https://cryptography.io/>`_.
* Due to the transition to cryptography, some features have been removed:

  * The ``tlsfeature`` extension is no longer supported. It will be again once cryptography adds support.
  * The ``msCodeInd``, ``msCodeCom``, ``msCTLSign``, ``msEFS`` values for the ExtendedKeyUsage extension are
    no longer supported. Support for these was largely academic anyway, so they most likely will not be added
    again.
  * ``TEXT`` is no longer a supported output format for dumping certificates.

* The ``keyUsage`` extension is now marked as critical for certificate authorities.
* Add the ``privilegeWithdrawn`` and ``aACompromise`` attributes for revocation lists.

.. _changelog-1.4.1:

******************
1.4.1 (2017-02-26)
******************

* Update requirements.
* Use `Travis CI <https://travis-ci.org>`_ for continuous integration. **django-ca** is now tested
  with Python 2.7, 3.4, 3.5, 3.6 and nightly, using Django 1.8, 1.9 and 1.10.
* Fix a few test errors for Django 1.8.
* Examples now consistently use 4096 bit certificates.
* Some functionality is now migrated to ``cryptography`` in the ongoing process to deprecate
  pyOpenSSL (which is no longer maintained).
* OCSPView now supports directly passing the public key as bytes. As a consequence, a bad
  certificate is now only detected at runtime.

.. _changelog-1.4.0:

******************
1.4.0 (2016-09-09)
******************

* Make sure that Child CAs never expire after their parents. If the user specifies an expiry after
  that of the parent, it is silently changed to the parents expiry.
* Make sure that certificates never expire after their CAs. If the user specifies an expiry after
  that of the parent, throw an error.
* Rename the ``--days`` parameter of the ``sign_cert`` command to ``--expires`` to match what we
  use for ``init_ca``.
* Improve help-output of ``--init-ca`` and ``--sign-cert`` by further grouping arguments into
  argument groups.
* Add ability to add CRL-, OCSP- and Issuer-URLs when creating CAs using the ``--ca-*`` options.
* Add support for the ``nameConstraints`` X509 extension when creating CAs. The option to the
  ``init_ca`` command is ``--name-constraint`` and can be given multiple times to indicate multiple
  constraints.
* Add support for the ``tlsfeature`` extension, a.k.a. "TLS Must Staple". Since OpenSSL 1.1 is
  required for this extension, support is currently totally untested.

.. _changelog-1.3.0:

******************
1.3.0 (2016-07-09)
******************

* Add links for downloading the certificate in PEM/ASN format in the admin interface.
* Add an extra chapter in documentation on how to create intermediate CAs.
* Correctly set the issuer field when generating intermediate CAs.
* ``fab init_demo`` now actually creates an intermediate CA.
* Fix help text for the ``--parent`` parameter for :command:`manage.py init_ca`.

.. _changelog-1.2.2:

******************
1.2.2 (2016-06-30)
******************

* Rebuild to remove old migrations accidentally present in previous release.

.. _changelog-1.2.1:

******************
1.2.1 (2016-06-06)
******************

* Add the ``CA_NOTIFICATION_DAYS`` setting so that watchers don't receive too many emails.
* Fix changing a certificate in the admin interface (only watchers can be changed at present).

.. _changelog-1.2.0:

******************
1.2.0 (2016-06-05)
******************

* **django-ca** now provides a complete :doc:`OCSP responder <ocsp>`.
* Various tests are now run with a precomputed CA, making tests much faster and output more predictable.
* Update lots of documentation.

.. _changelog-1.1.1:

******************
1.1.1 (2016-06-05)
******************

* Fix the ``fab init_demo`` command.
* Fix installation via ``setup.py install``, fixes
  `#2 <https://github.com/mathiasertl/django-ca/issues/2>`_ and `#4
  <https://github.com/mathiasertl/django-ca/issues/4>`_.  Thanks to Jon McKenzie for the fixes!

.. _changelog-1.1.0:

******************
1.1.0 (2016-05-08)
******************

* The subject given in the :command:`manage.py init_ca` and :command:`manage.py sign_cert` is now given in the
  same form that is frequently used by OpenSSL, ``/C=AT/L=...``.
* On the command line, both CAs and certificates can now be named either by their CommonName or
  with their serial. The serial can be given with only the first few letters as long as it's
  unique, as it is matched as long as the serial starts with the given serial.
* Expiry time of CRLs can now be specified in seconds. :command:`manage.py dump_crl` now uses the
  ``--expires`` instead of the old ``--days`` parameter.
* The admin interface now accounts for cases where some or all CAs are not usable because the private key is
  not accessible. Such a scenario might occur if the private keys are hosted on a different machine.
* The app now provides a generic view to generate CRLs. See :doc:`crl` for more information.
* Fix the display of the default value of the --ca arguments.
* Move this ChangeLog from a top-level Markdown file to this location.
* Fix shell example when issuing certificates.

.. _changelog-1.0.1:

******************
1.0.1 (2016-04-27)
******************

* Officially support Python2.7 again.
* Make sure that certificate authorities cannot be removed via the web interface.

.. _changelog-1.0.0:

******************
1.0.0 (2016-04-27)
******************

This represents a massive new release (hence the big version jump). The project
now has a new name (**django-ca** instead of just "certificate authority") and
is now installable via pip. Since versions prior to this release probably had no users (as it
wasn't advertised anywhere), it includes several incompatible changes.

General
=======

* This project now runs under the name **django-ca** instead of just "certificate authority".
* Move the git repository is now hosted at https://github.com/mathiasertl/django-ca.
* This version now absolutely assumes Python3. Python2 is no longer supported.
* Require Django  1.8 or later.
* django-ca is now usable as a stand-alone project (via git) or as a reusable app (via pip).

Functionality
=============

* The main app was renamed from ``certificate`` to ``django_ca``. See below for how to upgrade.

``manage.py`` interface
=======================

* :command:`manage.py` commands are now renamed to be more specific:

  * ``init`` -> ``init_ca``
  * ``sign`` -> ``sign_cert``
  * ``list`` -> ``list_certs``
  * ``revoke`` -> ``revoke_cert``
  * ``crl`` -> ``dump_crl``
  * ``view`` -> ``view_cert``
  * ``watch`` -> ``notify_expiring_certs``
  * ``watchers`` -> ``cert_watchers``

* Several new :command:`manage.py` commands:

  * ``dump_ca`` to dump CA certificates.
  * ``dump_cert`` to dump certificates to a file.
  * ``dump_ocsp_index`` for an OCSP responder, ``dump_crl`` no longer outputs this file.
  * ``edit_ca`` to edit CA properties from the command line.
  * ``list_cas`` to list available CAs.
  * ``view_ca`` to view a CA.

* Removed the :command:`manage.py remove` command.
* ``dump_{ca,cert,crl}`` can now output DER/ASN1 data to stdout.

.. _changelog-0.2.1:

******************
0.2.1 (2015-05-24)
******************

* Signed certificates are valid five minutes in the past to account for possible clock skew.
* Shell-scripts: Correctly pass quoted parameters to :command:`manage.py`.
* Add documentation on how to test CRLs.
* Improve support for OCSP.

.. _changelog-0.2:

****************
0.2 (2015-02-08)
****************

* The ``watchers`` command now takes a serial, like any other command.
* Reworked ``view`` command for more robustness.

  * Improve output of certificate extensions.
  * Add the ``-n``/``--no-pem`` option.
  * Add the ``-e``/``--extensions`` option to print all certificate extensions.
  * Make output clearer.

* The ``sign`` command now has

  * a ``--key-usage`` option to override the ``keyUsage`` extended attribute.
  * a ``--ext-key-usage`` option to override the ``extendedKeyUsage`` extended attribute.
  * a ``--ocsp`` option to sign a certificate for an OCSP server.

* The default ``extendedKeyUsage`` is now ``serverAuth``, not ``clientAuth``.
* Update the remove command to take a serial.
* Ensure restrictive file permissions when creating a CA.
* Add :file:`requirements-dev.txt`

.. _changelog-0.1:

****************
0.1 (2015-02-07)
****************

* Initial release
