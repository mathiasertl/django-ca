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
2.3.0 (TBR)
***********

Dependencies
============

* Drop support for ``josepy~=1.15.0``.

