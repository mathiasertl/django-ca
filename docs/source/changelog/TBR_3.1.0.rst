###########
3.1.0 (TBR)
###########

.. WARNING::

   Old database migrations have been removed in this release. You can upgrade to this release *only* from
   version 2.3.0 or later.

********
Settings
********

* :ref:`settings-ca-notification-days` can now be set using using an ISO 8601 timedelta string.
* Added :ref:`settings-ca-ocsp-response-cache-expires` and `CA_OCSP_RESPONSE_CACHE_EXPIRES` settings to
  configure :ref:`OCSP response caching <ocsp-response-caching>`.

*************
OCSP and CRLs
*************

* Implement :ref:`OCSP response caching <ocsp-response-caching>`.

************
Command-line
************

* :command:`manage.py notify_expiring_certs`:

  * The command now always sends all pending notifications. The ``--days`` parameter no longer has any effect
    and will be removed in ``django-ca==3.3.0``.
  * The command now uses the Celery task internally to send notifications, so it will return instantly if
    Celery is configured. The improvements described below thus also apply to this command.

* Add the :command:`manage.py generate_ocsp_responses` command to generate OCSP responses from the command
  line.

************
Celery tasks
************

* Add the :py:func:`~django_ca.tasks.notify_watchers` task to send notifications for expiring certificates
  in Celery:

  * The task remembers which notifications were already sent. It can thus be called multiple times a day to
    protect against outages.
  * In setups that use Celery, the task is configured to run every six hours.

* Add the :py:func:`~django_ca.tasks.generate_ocsp_responses` task to cache OCSP responses periodically.

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

***************************
Models and database support
***************************

* Cleaned up QuerySEt methods to ensure consistency and more readable code. QuerySet methods are now
  documented in the :doc:`model reference </python/models>`.
* Removed initial set of migrations, squashed migrations where added in ``django-ca==2.3.0``.
* Reduced the maximum length for the name of certificate authorities to 255, from 256. The field is indexed
  and MariaDB does not allow an index with a length greater then 255 characters.
* Names for watchers can now be up to 255 characters long (from 64).

************
Dependencies
************

* **BACKWARDS INCOMPATIBLE:** Dropped support for ``acme~=5.2.0`` and ``acme~=5.3.0``.
* Added support for ``cryptography~=47.0``, ``cryptography~=48.0`` and ``cryptography~=49.0``.
* Added support for ``pydantic~=2.13.0``.
* Added support for ``acme~=5.6.0``.

*******************
Deprecation notices
*******************

* This is the last release to support ``acme~=5.4.0`` and ``acme~=5.5.0``.
* This is the last release to support ``pydantic~=2.12.0``.
* This is the last release to support ``cryptography~=46.0``, ``cryptography~=47.0`` and
  ``cryptography~=48.0``.

*******************
Setup and packaging
*******************

* Switch to `hatch <https://github.com/pypa/hatch>`_ to build Python Wheels.
