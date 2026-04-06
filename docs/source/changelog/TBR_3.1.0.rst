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

* Switch to `hatch <https://github.com/pypa/hatch>`_ to build Python Wheels.

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

* Support for passing an ``int`` as the `expires` parameter for :py:class:`~django_ca.views.OCSPView` was
  removed (deprecated since 3.0.0).

************
Dependencies
************

* **BACKWARDS INCOMPATIBLE:** Dropped support for ``acme~=5.2.0`` and ``acme~=5.3.0``.

*******************
Deprecation notices
*******************

None yet.
