##############
ACMEv2 support
##############

**django-ca** has preliminary ACMEv2 support that allows you to retrieve certificates via certbot or other
standard ACME clients.

.. WARNING::

   Support for ACME is preliminary and must be explicitly activated. Several features are not yet implemented.
   Use this feature only with the necessary caution.

*********************
Enabling ACME support
*********************

To enable ACME support, simply set ``CA_ENABLE_ACME=True`` in your settings.

You must enable ACME for each CA individually, either in the admin interface or view the ``edit_ca``
management command.

*****************
Known limitations
*****************

ACMEv2 support is preliminary, known to be incomplete and may contain critical bugs. But at least basic
certificate issuance is working.

The following things are known to not yet work:

* Challenge types others then ``http-01``.
* Certificate revocation
* Pre-Authorization for certificates
* Account update and deactivation
* External account bindings
* CAA validation (django-ca will happily issue certificates for google.com etc.)

********
Settings
********

.. _settings-ca-acme-enable:

CA_ENABLE_ACME
   Default: ``False``

   Enable ACMEv2 support. Without it, all functionality is disabled.

CA_ACME_MAX_CERT_VALIDITY
   Default: ``90``

   Maximum time in days that certificate via ACMEv2 can be valid. Can also be set to a timedelta object.

CA_ACME_DEFAULT_CERT_VALIDITY
   Default: ``90``

   Default time in days that certificate via ACMEv2 can be valid. Can also be set to a timedelta object.

CA_ACME_ACCOUNT_REQUIRES_CONTACT
   Default: ``True``

   Set to false to allow creating ACMEv2 accounts without an email address.


*********
Standards
*********

* `RFC 8555: ACMEv2 <https://tools.ietf.org/html/rfc8555>`_
* `RFC 7515: JSON Web Signature (JWS) <https://tools.ietf.org/html/rfc7515>`_
* `RFC 7517: JSON Web Key (JWK) <https://tools.ietf.org/html/rfc7515>`_
* `RFC 7638: JSON Web Key (JWK) Thumbprint <https://tools.ietf.org/html/rfc7638>`_

****************
Tipps and tricks
****************

Query LE::

   curl -v https://acme-v02.api.letsencrypt.org/directory

Use local server::

   certbot register --agree-tos -m user@localhost \
      --config-dir=.certbot/config/ --work-dir=.certbot/work/ --logs-dir=.certbot/logs \
      --server http://localhost:8000/django_ca/acme/directory/

   certbot certonly --standalone \
      --config-dir=.certbot/config/ --work-dir=.certbot/work/ --logs-dir=.certbot/logs \
      --server http://localhost:8000/django_ca/acme/directory/ \
      -d test.example.com

Saving debug log to /home/mertl/git/mati/django-ca/.certbot/logs/letsencrypt.log


base64url encoding
==================

The ACME library does that with `josepy <https://pypi.org/project/josepy/>`_
(which is **not** the similar/forked? "python-jose")::

   >>> import josepy as jose
   >>> jose.b64encode(b'test')
   b'dGVzdA'
   >>> jose.b64decode(b'dGVzdA')
   b'test'
