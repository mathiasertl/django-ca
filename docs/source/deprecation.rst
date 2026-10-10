####################
Deprecation timeline
####################

This page shows

***************
4.0.0 (Q1 2027)
***************

* Support for Python 3.11 will be dropped.
* Support for DSA keys will be dropped.
* The defaults for :ref:`CA_DEFAULT_EXPIRES <settings-ca-default-expires>` and :ref:`CA_ACME_MAX_CERT_VALIDITY
  <CA_ACME_MAX_CERT_VALIDITY>` will be reduced to 47 days (announced with 3.0.0).

Docker images
=============

* Support for Alpine-based Docker images will be dropped (deprecated with 3.2.0).
* Support for old wrapper scripts (``celery.sh``, ``celerybeat.sh`` and ``gunicorn.sh``) will be dropped.
  Use the new names instead:

  ================= ========================
  Old name          New name
  ================= ========================
  ``celerybeat.sh`` ``django-ca-celerybeat``
  ``celery.sh``     ``django-ca-celery``
  ``gunicorn.sh``   ``django-ca-gunicorn``
  ================= ========================
