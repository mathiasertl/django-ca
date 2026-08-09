###########
3.2.0 (TBR)
###########

********
Settings
********

* Add :ref:`CA_ACME_NONCE_TIMEOUT <CA_ACME_NONCE_TIMEOUT>` to configure how long an ACME nonce remains
  valid after being issued.
* Add :ref:`CA_ACME_JWS_SIGNATURE_ALGORITHMS <CA_ACME_JWS_SIGNATURE_ALGORITHMS>` to restrict which JWS
  signature algorithms are accepted for ACME requests.

******
ACMEv2
******

* Implement IP address validation according to `RFC 8738 <https://datatracker.ietf.org/doc/html/rfc8738>`_.
  This allows you to create certificates for IP addresses using ACMEv2.
* Implement Account Key Rollover as specified in `RFC 8555, section 7.3.5
  <https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.5>`_.
* Implement Orders List endpoint as specified in `RFC 8555, section 7.1.2.1
  <https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.2.1>`_.
* ACME nonce lifetime is now configured independently of the default cache configuration via the
  :ref:`CA_ACME_NONCE_TIMEOUT <CA_ACME_NONCE_TIMEOUT>` setting mentioned above. This ensures that a cache
  configured with an infinite lifetime won't cause nonces to stay valid forever.
* No longer follow redirects when validating ``http-01`` challenges.
* The JWS signature algorithm is now validated against
  :ref:`CA_ACME_JWS_SIGNATURE_ALGORITHMS <CA_ACME_JWS_SIGNATURE_ALGORITHMS>`. Symmetric HMAC algorithms
  (``HS256``, ``HS384``, ``HS512``) are no longer accepted. The algorithm is also validated for the inner
  JWS in key-rollover requests.

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

* Removed the ``cache_crls`` command (deprecated since ``django-ca==3.0.0``). Use :command:`generate_crls`
  instead.
* Removed the ``regenerate_ocsp_keys`` command (deprecated since ``django-ca==3.0.0``). Use
  :command:`generate_ocsp_keys` instead.

***************
Admin interface
***************

No changes yet.

************
Celery tasks
************

* Removed the ``django_ca.tasks.cache_crl`` task (deprecated since ``django-ca==3.0.0``). Use
  :py:func:`django_ca.tasks.generate_crl` instead.
* Removed the ``django_ca.tasks.cache_crls`` task (deprecated since ``django-ca==3.0.0``). Use
  :py:func:`django_ca.tasks.generate_crls` instead.

**********
Python API
**********

No changes yet.

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

* Add support for ``cryptography~=50.0``.
* Add support for ``acme~=5.7.0``.
* **BACKWARDS INCOMPATIBLE:** Dropped support for ``cryptography~=46.0``, ``cryptography~=47.0`` and
  ``cryptography~=48.0``.
* **BACKWARDS INCOMPATIBLE:** Dropped support for ``pydantic~=2.12.0``.
* **BACKWARDS INCOMPATIBLE:** Dropped support for ``acme~=5.4.0`` and ``acme~=5.5.0``.

*******************
Deprecation notices
*******************

None yet.

*******************
Setup and packaging
*******************

* Docker images no longer include command-line clients for PostgreSQL and MariaDB, to minimize the attack
  surface. As a consequence, :command:`manage.py dbshell` no longer works out of the box.
* Docker images now include signed SBOMs, see :ref:`quickstart-docker-verify-sbom-attestations`.
