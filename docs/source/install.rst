############
Installation
############

There are multiple ways of installing **django-ca**. Each supported installation method has its own quickstart
guide:

* :doc:`quickstart/docker_compose`: By far the easiest, fastest and most reliable way.
* :doc:`quickstart/as_app`: If you want to integrate django-ca into your existing Django project.
* :doc:`quickstart/from_source`: If you want to install the project from source (or want to use it as a
  template for a totally different platform).
* :doc:`quickstart/docker`: If you already have web server, database etc. set up or as a template for
  orchestration platforms such as Docker Swarm.

.. _regular-tasks-explanation:

**********************
Required regular tasks
**********************

**django-ca** requires a few tasks to be run regularly in a cron-style manner.

If you chose an installation method that includes the full Django project (e.g. using Compose, Docker or
from source), everything is already set up for you and you can skip this section entirely, unless you want to
mess with some very specific settings.

If chose to use **django-ca** as a Django app, you have to :ref:`setup regular tasks manually
<quickstart-as-app-setup-regular-tasks>`.

Regenerate Certificate Revocation Lists (CRLs)
==============================================

The :py:func:`django_ca.tasks.cache_crls` Celery task is responsible for regenerating CRLS before they
expire. By default, the Celery task is run a bit less then once a day.

CRLs expire after one day by default, but this can be changed via :ref:`CA_CRL_PROFILES
<settings-ca-crl-profiles>`. If you change this setting, the frequency of this task must be *higher* then
that setting.

If you use **django-ca** as a Django app and do not want to use Celery, execute :command:`python manage.py
cache_crls` with a similar frequency.

Regenerate OCSP responder certificates
======================================

The :py:func:`django_ca.tasks.generate_ocsp_keys` Celery task is responsible for regenerating OCSP keys
before they expire. By default, the Celery task is run every hour.

Certificates are not renewed unless they expire within the interval defined by
:ref:`CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL <settings-ca-ocsp-responder-certificate-renewal>`. If you
change that setting, the frequency of this task must be *higher* then that setting.

If you use **django-ca** as a Django app and do not want to use Celery, execute :command:`python manage.py
regenerate_ocsp_keys` with a similar frequency.

Clean up ACME database records
==============================

The :py:func:`django_ca.tasks.acme_cleanup` Celery task is responsible for cleaning up database entries
related to ACME operations, e.g. expired ACME orders. The task runs every five minutes by default.

This task is not required if you have disabled ACME via :ref:`CA_ENABLE_ACME <settings-acme-enable-acme>`.

.. _http-explanation:

****************
Why plain HTTP?!
****************

OCSP and CRL access (protocols used to obtain the revocation status of certificates) usually work via HTTP,
**not** HTTPS. Clients would need to obtain the revocation status of the certificate used for the HTTPS
connection using that same HTTPS connection. Responses are signed, so using HTTP is not considered a security
vulnerability.

Just in case you doubt the above: check how publicly trusted and widely used certificate authorities set the
:ref:`ca-example-crlDistributionPoints` and :ref:`ca-example-AuthorityInfoAccess` extensions.

However, only CRL, OCSP and issuer information needs to be available via HTTP.  If you use ``/ca`` as path in
your URL configuration (like in the example above), you only need ``/ca/issuer/``, ``/ca/ocsp/`` and
``/ca/crl/`` available via HTTP.
