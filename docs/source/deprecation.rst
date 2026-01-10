####################
Deprecation timeline
####################

***********
4.0.0 (TBR)
***********

* The defaults for :ref:`CA_DEFAULT_EXPIRES <settings-ca-default-expires>` and :ref:`CA_ACME_MAX_CERT_VALIDITY
  <CA_ACME_MAX_CERT_VALIDITY>` will be reduced to 47 days (announced with 3.0.0).

***********
3.1.0 (TBR)
***********

* Support for using an ``int`` for `expires` in :py:class:`~django_ca.views.OCSPView` will be removed
  (deprecated since 3.0.0).
