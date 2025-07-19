####################
Deprecation timeline
####################

***********
2.5.0 (TBR)
***********

* Non-squashed migrations will be removed. Users of older versions will first have to update to ``2.3.x``
  or ``2.4.x``.
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


