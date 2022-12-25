###########
Development
###########

**********
Setup demo
**********

You can set up a demo using ``dev.py init-demo``. First create a minimal
``localsettings.py`` file (in ``ca/ca/localsettings.py``)::

   DEBUG = True
   SECRET_KEY = "whatever"

And then simply run ``python dev.py init-demo`` from the root directory of your project.

Development web server via SSL
==============================

.. highlight:: console

To test a certificate in your web server, first install :command:`stunnel4`, in Debian/Ubuntu simply do::

   $ sudo apt update
   $ sudo apt install stunnel4

the root certificate authority in your browser, then run ``stunnel4`` and ``manage.py runserver`` in two
separate shells::

   $ stunnel4 .stunnel4.conf

There is also a second configuration file using a revoked certificate. If you use it, browsers will display an
error::

   $ stunnel4  .stunnel4-revoked.conf

You can now start your development web server normally::

   $ DJANGO_SETTINGS_MODULE=ca.demosettings python manage.py runserver

... and visit https://localhost:8443.

**************
Run test-suite
**************

To run the test-suite, simply execute::

   $ python dev.py test

... or just run some of the tests::

   $ python dev.py test --suite=tests_command_dump_crl

To generate a coverage report::

   $ python dev.py coverage

***********************
Useful OpenSSL commands
***********************

Verification
============

Verify a certificate signed by a root CA (``cert.crt`` could also be an intermediate CA)::

   $ openssl verify -CAfile ca.crt cert.crt

If you have an intermediate CA::

   $ cat child.pem root.pem > cafile.pem
   $ openssl verify -CAfile cafile.pem cert.crt

Verify that a certificate belongs to a certain private key by matching the checksum::

   $ openssl x509 -noout -modulus -in cert.pem | openssl sha1
   $ openssl rsa -noout -modulus -in cert.key | openssl sha1

CRLs
====

Convert a CRL to text on stdout::

   $ openssl crl -inform der -in crl.der -noout -text
   Certificate Revocation List (CRL):
           Version 2 (0x1)
           Signature Algorithm: sha512WithRSAEncryption
           Issuer: CN = Intermediate CA
           Last Update: Dec 28 14:10:04 2020 GMT
           Next Update: Dec 29 14:10:04 2020 GMT
   ...
   $ openssl crl -inform pem -in crl.pem -noout -text
   ...

Convert a CRL to PEM to a file::

   $ openssl crl -inform der -in crl.der -outform pem -out crl.pem

Verify a certificate using a CRL (requires CRL in PEM format)::

   $ openssl verify -CAfile cabundle.pem -crl_check -CRLfile crl.pem cert.pem
   cert.pem: OK

Verify CRL by automatically downloading the CRL::

   $ openssl verify -CAfile cabundle.pem -crl_check -crl_download cert.pem
   cert.pem: OK

OCSP
====

Get the OCSP responder URL from the certificate (:command:`openssl` cannot get it from the cert like with
``verify -crl_download``)::

   $ openssl x509 -in cert.pem -noout -text | grep -i ocsp
   OCSP - URI:http://ca.example.com/django_ca/ocsp/4E9D186B93AB38FBB8FA36BE4AC28098A1AA2647/cert/

Verify a certificate using OCSP::

   $ openssl ocsp -CAfile root.pem -issuer child.pem -cert cert.pem
   >     -url http://... -text
   ...
   Response verify OK
   cert.pem: good
           This Update: Dec 28 14:34:28 2020 GMT
           Next Update: Dec 28 15:34:28 2020 GMT

Conversion
==========

Convert a PEM formatted public key to DER::

   $ openssl x509 -in pub.pem -outform der -out pub.der

Convert a PEM formatted **private** key to DER::

   $ openssl rsa -in priv.pem -outform der -out priv.der

Convert a PKCS#7 file to PEM (Let's Encrypt CA Issuer field) (see also :manpage:`pkcs7.1ssl`)::

   $ openssl pkcs7 -inform der -in letsencrypt.p7c -print_certs -outform pem -out letsencrypt.pem
