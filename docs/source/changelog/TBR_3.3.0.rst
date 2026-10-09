###########
3.3.0 (TBR)
###########

********
Settings
********

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

* **BACKWARDS INCOMPATIBLE:** Dropped support for ``cryptography~=49.0``.
* **BACKWARDS INCOMPATIBLE:** Dropped support for ``acme~=5.6.0`` and ``acme~=5.7.0``.

*******************
Deprecation notices
*******************

* This is the last version to support ``Python~=3.11.0``.
* This is the last version to support DSA keys (cryptography is also deprecating and eventually removing
  support).
* This is the last version to support Alpine-based Docker images.

*******************
Setup and packaging
*******************

* Docker images now includes bytecode for improved startup times (at the expense of larger images). The
  bytecode adds about 33 MB to the image size (227 MB -> 260 MB), but startup time of a simple ``manage -h``
  invocation improves from six seconds to three seconds.
