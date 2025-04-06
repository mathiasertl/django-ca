####################
Deprecation timeline
####################

***********
2.5.0 (TBR)
***********

* The ``CA_CUSTOM_APPS`` setting will be removed. Use :ref:`EXTEND_INSTALLED_APPS
  <settings-extend-installed-apps>` instead.

REST API
========

* The old API endpoint (``/ca/{ca_serial}/revoke/{certificate_serial}/``) for revoking certificates will be
  removed. Use ``/ca/{ca_serial}/certs/{certificate_serial}/revoke/`` instead. Deprecated since
  ``django-ca==2.3.0``.

***********
2.4.0 (TBR)
***********

Command-line
============

* :command:`manage.py resign_cert` will no longer allow you to change certificate details when resigning a
  certificate. The ``--ca``, ``--subject``, ``--profile``, ``--algorithm``,
  ``--ocsp-responder``, ``--ca-issuer``, ``--policy-identifier``, ``--certification-practice-statement``,
  ``--user-notice``, ``--crl-full-name``, ``--issuer-alternative-name``, ``--extended-key-usage``,
  ``--key-usage``, ``--ocsp-no-check``, ``--subject-alternative-name`` and ``--tls-feature``, as well as all
  arguments to mark extensions as (not) critical, will be removed. Deprecated since ``django-ca==2.3.0``.
* :command:`manage.py regenerate_ocsp_keys` will no longer allow specifying certificate details for delegate
  certificates. The ``--profile``, ``--expires``, ``--key-type``, ``--key-size``, ``--elliptic-curve`` and
  ``--algorithm`` arguments will be removed.

Dependencies
============

* Drop support for ``Celery~=5.4.0``. Deprecated since ``django-ca==2.3.0``.

***********
2.3.0 (TBR)
***********

Dependencies
============

* Drop support for ``josepy~=1.15.0``.

