########################################
Host a Certificate Revocation List (CRL)
########################################

A Certificate Revocation List (CRL) contains all revoked certificates signed by
a certificate authority. Having a CRL is completely optional (e.g. `Let's
Encrypt <https://letsencrypt.org/>`_ certificates don't have one).

A URL to the CRL is usually included in the certificates (in the
``crlDistributionPoints`` x509 extension) so clients can fetch the CRL and
verify that the certificate has not been revoked. Some services (e.g. OpenVPN)
also just keep a local copy of a CRL.

.. NOTE:: CRLs are usually hosted via HTTP, **not** HTTPS. CRLs are always
   signed, so hosting them via HTTP is not a security vulnerability. Further,
   you cannot verify the the certificate used when fetching the CRL
   anyway, since you would need the CRL for that.

*******************************
Add CRL URL to new certificates
*******************************

To include the URL to a CRL in newly issued certificates (you cannot add it to
already issued certificates, obviously), either set it in the admin interface or
via the command line:

.. code-block:: console

   $ python manage.py list_cas
   34:D6:02:B5:B8:27:4F:51:9A:16:0C:B8:56:B7:79:3F - Root CA
   $ python manage.py edit_ca --crl-url=http://ca.example.com/crl.pem \
   >     34:D6:02:B5:B8:27:4F:51:9A:16:0C:B8:56:B7:79:3F


.. _crl-generic:

******************************
Use generic view to host a CRL
******************************

**django-ca** provides the generic view :py:class:`~django_ca.views.CertificateRevocationListView`
to provide CRLs via HTTP.

If you installed **django-ca** as a full project, a default CRL is already available for all CAs.
If you installed django-ca on "ca.example.com", the CRL is available at
``http://ca.example.com/django_ca/crl/<serial>/``. If you installed django-ca as an app, you only
need to include ``django_ca.urls`` in your URL conf at the appropriate location.

The default CRL is in the ASN1/DER format, signed with sha512 and refreshed every ten minutes.
This is fine for TLS clients that use CRLs and is in fact similar to what public CAs use (see
:ref:`ca-example-crlDistributionPoints`). If you want to change any of these settings, you can
override them as parameters in a URL conf::

   from OpenSSL import crypto
   from django_ca.views import CertificateRevocationListView

   urlpatterns = [
      # ... your other patterns

      # We need a CRL in PEM format with a sha256 digest
      url(r'^crl/(?P<serial>[0-9A-F:]+)/$', 
          CertificateRevocationListView.as_view(
              type=crypto.FILETYPE_PEM,
              digest='sha256',
              content_type='text/plain',
          ), 
          name='sha256-crl')),
   ]

If you do not want to include the automatically hosted CRL, please set ``CA_PROVIDE_GENERIC_CRL``
to ``False`` in your settings.

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

How and where to host the file is entirely up to you. If you run a Django project with a webserver
already, one possibility is to dump it to your ``MEDIA_ROOT`` directory.
