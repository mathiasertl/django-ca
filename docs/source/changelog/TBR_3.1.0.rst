###########
3.1.0 (TBR)
###########

********
Settings
********

No changes yet.

*******************
Setup and packaging
*******************

No changes yet.

******
ACMEv2
******

No changes yet.

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

No changes yet.

***************
Admin interface
***************

No changes yet.

************
Celery tasks
************

No changes yet.

**********
Python API
**********

* ``django_ca.models.CertificateAuthority.cache_crls`` was removed. Use
  :py:func:`~django_ca.models.CertificateAuthority.generate_crls` instead.

*****
Views
*****

No changes yet.

************
Dependencies
************

No changes yet.

*******************
Deprecation notices
*******************

None yet.
