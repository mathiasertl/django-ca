###########
Development
###########

.. autoclass:: django_ca.tests.base.DjangoCATestCase
   :members:
   :exclude-members: assertRaisesRegex

**********
Setup demo
**********

You can set up a demo using ``dev.py init-demo``. First create a minimal
``localsettings.py`` file (in ``ca/ca/localsettings.py``)::

   DEBUG = True
   SECRET_KEY = "whatever"

And then simply run ``python dev.py init-demo`` from the root directory of your project.

Development webserver via SSL
=============================

To test a certificate in your webserver, first install stunnel, in Debian/Ubuntu simply do:

.. code-block:: console

   sudo apt-get install stunnel4

the root certificate authority in your browser, then
run ``stunnel4`` and ``manage.py runserver`` in two separate shells:

.. code-block:: console

   $ stunnel4 .stunnel4.conf

There is also a second config file using a revoked certificate. If you use it, browsers will display an error.

.. code-block:: console

   $ stunnel4  .stunnel4-revoked.conf

You can now start your development webserver normally:

.. code-block:: console

   $ DJANGO_SETTINGS_MODULE=ca.demosettings python manage.py runserver

... and visit https://localhost:8443.

**************
Run test-suite
**************

To run the test-suite, simply execute::

   python dev.py test

... or just run some of the tests::

   python dev.py test --suite=tests_command_dump_crl

To generate a coverate report::

   python dev.py coverage

***********************
Useful OpenSSL commands
***********************

.. highlight:: none

Verification
============

Verify a certificate signed by a root CA (``cert.crt`` could also be an
intermediate CA)::

   openssl verify -CAfile ca.crt cert.crt

If you have an intermediate CA::
   
   cat child.pem root.pem > cafile.pem
   openssl verify -CAfile cafile.pem cert.crt

Verify that a certificate belongs to a certain private key by matching the checksum::

   openssl x509 -noout -modulus -in cert.pem | openssl sha1
   openssl rsa -noout -modulus -in cert.key | openssl sha1

CRLs
====

Convert a CRL to text on stdout::

   openssl crl -inform der -in sfsca.crl -noout -text

Convert a CRL to PEM to a file::

   openssl crl -inform der -in sfsca.crl -outform pem -out test.pem

Verify a certificate using a CRL::

   openssl verify -CAfile files/ca_crl.pem -crl_check cert.pem

OCSP
====

Run a OCSP responder::

   openssl ocsp -index files/ocsp_index.txt -port 8888 \
      -rsigner files/localhost.pem -rkey files/localhost.key \
      -CA ca.pem -text

Verify a certificate using OCSP::

  openssl ocsp -CAfile {root-ca-serial}.pem -issuer {intermediate-ca-serial}.pem -cert host1.example.com.pem
      -url http://localhost:8000/django_ca/ocsp/{intermediate-ca-serial}/cert/ -text

Conversion
==========

Convert a PEM formatted public key to DER::

   openssl x509 -in pub.pem -outform der -out pub.der

Convert a PEM formatted **private** key to DER::

   openssl rsa -in priv.pem -outform der -out priv.der

Convert a p7c/pkcs7 file to PEM (Let's Encrypt CA Issuer field) (see also
:manpage:`pkcs7(1SSL)` -
`online <https://www.openssl.org/docs/manmaster/apps/pkcs7.html>`_)::

   openssl pkcs7 -inform der -in letsencrypt.p7c -print_certs \
      -outform pem -out letsencrypt.pem

****************
ACME development
****************

Standards
=========

* `RFC 8555: ACMEv2 <https://tools.ietf.org/html/rfc8555>`_
* `RFC 7515: JSON Web Signature (JWS) <https://tools.ietf.org/html/rfc7515>`_
* `RFC 7517: JSON Web Key (JWK) <https://tools.ietf.org/html/rfc7515>`_
* `RFC 7638: JSON Web Key (JWK) Thumbprint <https://tools.ietf.org/html/rfc7638>`_

Tipps and tricks
================

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
