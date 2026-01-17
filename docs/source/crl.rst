########################################
Host a Certificate Revocation List (CRL)
########################################

A Certificate Revocation List (CRL) contains all revoked certificates signed by a certificate authority.
Having a CRL is completely optional (many certificate authorities don't have one).

A URL to the CRL is usually included in the certificates (in the ``crlDistributionPoints`` x509 extension) so
clients can fetch the CRL and verify that the certificate has not been revoked. Some services (e.g. OpenVPN)
also just keep a local copy of a CRL.

.. NOTE:: CRLs are usually hosted via HTTP, **not** HTTPS. CRLs are always signed, so hosting them via HTTP is
   not a security vulnerability. Further, you cannot verify the the certificate used when fetching the CRL
   anyway, since you would need the CRL for that.


****************
Use default CRLs
****************

If you have (correctly) configured a :ref:`CA_DEFAULT_HOSTNAME <settings-ca-default-hostname>` and setup the
web server under that URL, **django-ca** will automatically serve CRLs under the correct URL.

If you use django-ca :doc:`as Django app </quickstart/as_app>`, you have to make sure that you either have
a `celery beat <https://docs.celeryq.dev/en/latest/userguide/periodic-tasks.html>`_ daemon running or run
:command:`manage.py generate_crls` as a regular, daily CRON job. If you have neither, django-ca will try to
sign a CRL on the fly, implying that the CAs private key must be available on the web server.

All other supported setups (Docker Compose, etc) automatically generate CRLs using celery beat.

Override default hostname
=========================

By default, **django-ca** will generate CRL URLs based on :ref:`CA_DEFAULT_HOSTNAME
<settings-ca-default-hostname>`. If you want to generate a CA to use a different hostname (e.g. a CA for
internal use only, where you can reach the CRL under a local domain), you can override the default hostname:

.. code-block:: console

   $ python manage.py init_ca \
   >     --default-hostname=ca.local.tld
   >     ...

... or disable it altogether, in which case the CA will not contain any URLs:

.. code-block:: console

   $ python manage.py init_ca \
   >     --no-default-hostname
   >     ...

Customize CRL URLs
==================

If you want to statically generate CRLs and copy them to a custom location (e.g. for performance reasons), you
can customize the CRL URLs used for a CA when generating it (note that you cannot set a CRL URL in the CA
certificate if it is a root CA):

.. code-block:: console

   $ python manage.py init_ca \
   >     --parent=... \
   >     --crl-url=http://custom.example.com/cert.crl \
   >     --ca-crl-url=http://custom.example.com/ca.crl \
   >     ...

You can also change the CRL URL for newly issued certificates:

.. code-block:: console

   $ python manage.py list_cas
   34:D6:02:B5:B8:27:4F:51:9A:16:0C:B8:56:B7:79:3F - Root CA
   $ python manage.py edit_ca --crl-url=http://ca.example.com/crl.pem \
   >     34:D6:02:B5:B8:27:4F:51:9A:16:0C:B8:56:B7:79:3F

****************
Host custom CRLs
****************

**django-ca** hosts CRLs in a format that is usually understood by CRL clients, but you might want to host
CRLs in a different format in your own URL configuration::

   from cryptography.hazmat.primitives import hashes
   from cryptography.hazmat.primitives.serialization import Encoding
   from django_ca.views import CertificateRevocationListView

   urlpatterns = [
      ...

      # we need a PEM CRL signed with SHA256 for some reason:
      path('<hex:serial>.pem', views.CertificateRevocationListView.as_view(
         type=Encoding.PEM,
         digest=hashes.SHA256()
      ), name='custom-crl'),
   ]


.. autoclass:: django_ca.views.CertificateRevocationListView
   :members:


*********************
Write a CRL to a file
*********************

You can generate the CRL with the ``manage.py dump_crl`` command::

   $ python manage.py dump_crl -f PEM /var/www/crl.pem

.. NOTE:: The ``dump_crl`` command uses the first enabled CA by default, you can
   force a particular CA with ``--ca=<serial>``.

CRLs expire after a certain time (default: one day, configure with ``--expires=SECS``), so you must
periodically regenerate it, e.g. via a cron-job.

How and where to host the file is entirely up to you. If you run a Django project with a web server
already, one possibility is to dump it to your ``MEDIA_ROOT`` directory.
