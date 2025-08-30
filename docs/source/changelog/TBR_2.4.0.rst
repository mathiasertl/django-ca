###########
2.4.0 (TBR)
###########

* OCSP responder certificates now have an empty subject.
* Fix configuring CRL reasons for CRL distribution points for signing certificates.

************
Command-line
************

* **BACKWARDS INCOMPATIBLE:**  :command:`manage.py regenerate_ocsp_keys`: Removed the ``--key-type``,
  ``--key-size``, ``--elliptic-curve``, ``--profile``, ``algorithm`` and ``--expires`` parameters (deprecated
  since ``django-ca~=2.3.0``).
* :command:`manage.py resign_cert`:

  * **BACKWARDS INCOMPATIBLE:**  :command:`manage.py resign_cert`: Removed the ``--ca``, ``--subject``,
    ``--profile``, ``--algorithm``, ``--ocsp-responder``, ``--ca-issuer``, ``--policy-identifier``,
    ``--certification-practice-statement``, ``--user-notice``, ``--crl-full-name``,
    ``--issuer-alternative-name``, ``--extended-key-usage``, ``--key-usage``, ``--ocsp-no-check``,
    ``--subject-alternative-name`` and ``--tls-feature``, as well as all arguments to mark extensions as (not)
    critical (deprecated since ``django-ca~=2.3.0``).

    If you want to resign a certificate with other parameters, simply sign a new one with the same CSR.
  * Do not copy the IssuerAlternativeName and FreshestCRL extensions from the source certificate (the
    certificate authority should provide it instead).
  * Unrecognized extensions (those not supported by cryptography) are now copied over verbatim from the
    source certificate.

********
REST API
********

* Implement endpoint to fetch profiles (fixes (`#168 <https://github.com/mathiasertl/django-ca/issues/168>`_).
* Fix internal server error (HTTP 500) when authenticating with a user that does not exist.

***************
Admin interface
***************

* Fix clearing/updating extensions when a new certificate authority is selected while signing certificates.

************
Dependencies
************

* **BACKWARDS INCOMPATIBLE:** Dropped support for ``pydantic~=2.10.0``.
* **BACKWARDS INCOMPATIBLE:** Dropped support for ``acme~=3.2.0``, ``acme~=3.3.0`` and ``acme~=4.0.0``.

**********
Python API
**********

* :py:func:`CertificateManager.objects.create_cert()
  <django_ca.managers.CertificateManager.create_cert>`
  and :py:func:`Profile.create_cert() <django_ca.profiles.Profile.create_cert>` now allow creating a
  certificate with neither a common name nor a Subject Alternative Name extension via the
  `allow_empty_subject` flag.
* **BACKWARDS INCOMPATIBLE:** Attributes in :py:mod:`django_ca.typehints` have been renamed to ensure
  naming consistency:

  ===================================== =============================================================
  old name                              new name
  ===================================== =============================================================
  ``AccessMethods``                     :attr:`~django_ca.typehints.AccessMethodName`
  ``AllowedHashTypes``                  :attr:`~django_ca.typehints.SignatureHashAlgorithm`
  ``CertificateExtensionKeys``          :attr:`~django_ca.typehints.CertificateExtensionKey`
  ``ConfigurableExtensionKeys``         :attr:`~django_ca.typehints.ConfigurableExtensionKey`
  ``EllipticCurves``                    :attr:`~django_ca.typehints.EllipticCurveName`
  ``EndEntityCertificateExtensionKeys`` :attr:`~django_ca.typehints.EndEntityCertificateExtensionKey`
  ``ExtensionKeys``                     :attr:`~django_ca.typehints.ExtensionKey`
  ``GeneralNames``                      :attr:`~django_ca.typehints.GeneralName`
  ``HashAlgorithms``                    :attr:`~django_ca.typehints.SignatureHashAlgorithmName`
  ``KeyUsages``                         :attr:`~django_ca.typehints.KeyUsage`
  ``LogEntryTypes``                     :attr:`~django_ca.typehints.LogEntryTypeName`
  ===================================== =============================================================

* **BACKWARDS INCOMPATIBLE:** Attributes in :py:mod:`django_ca.constants` have been renamed to ensure
  naming consistency:

  ======================== ===========================================================
  old name                 new name
  ======================== ===========================================================
  ``HASH_ALGORITHM_NAMES`` :attr:`~django_ca.constants.SIGNATURE_HASH_ALGORITHM_NAMES`
  ``HASH_ALGORITHM_TYPES`` :attr:`~django_ca.constants.SIGNATURE_HASH_ALGORITHM_TYPES`
  ======================== ===========================================================
