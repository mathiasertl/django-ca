####################
Deprecation timeline
####################

This page shows

***************
4.0.0 (Q1 2027)
***************

* Support for Python 3.11 will be dropped.
* The defaults for :ref:`CA_DEFAULT_EXPIRES <settings-ca-default-expires>` and :ref:`CA_ACME_MAX_CERT_VALIDITY
  <CA_ACME_MAX_CERT_VALIDITY>` will be reduced to 47 days (announced with 3.0.0).

***************
3.3.0 (Q4 2026)
***************

* The ``--days`` parameter for the `notify_expiring_certs` management command will be removed (deprecated
  since 3.1.0).

***************
3.2.0 (Q3 2026)
***************

* Support for ``cryptography~=49.0`` and ``acme~=5.6.0`` will be dropped.
* The `cache_crls` management command will be removed, used `generate_crls` instead (deprecated since 3.0.0).
* The `regenerate_ocsp_keys` management command will be removed, use `generate_ocsp_keys` instead (deprecated
  since 3.0.0).
