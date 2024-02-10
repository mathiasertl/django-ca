#############
Tips & Tricks
#############

******************************
Development web server via TLS
******************************

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

   $ python ca/manage.py runserver

... and visit https://localhost:8443.

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

   $ openssl ocsp -CAfile root.pem -issuer child.pem -cert cert.pem \
   >     -url http://... -text
   ...
   Response verify OK
   cert.pem: good
           This Update: Dec 28 14:34:28 2020 GMT
           Next Update: Dec 28 15:34:28 2020 GMT

For Let's Encrypt, the following command can be used, with ``full-chain.pem`` being the full certificate
chain, ``intermediate.pem`` being the cert that directly signed the certificate and ``cert.pem`` being the
server certificate::

   $ openssl ocsp -CAfile full-chain.pem -issuer intermediate.pem -cert cert.pem -url http://r3.o.lencr.org/ \
   >  -resp_text -req_text -no_nonce

Conversion
==========

Convert a PEM formatted public key to DER::

   $ openssl x509 -in pub.pem -outform der -out pub.der

Convert a PEM formatted **private** key to DER::

   $ openssl rsa -in priv.pem -outform der -out priv.der

Convert a PKCS#7 file to PEM (Let's Encrypt CA Issuer field) (see also :manpage:`pkcs7.1ssl`)::

   $ openssl pkcs7 -inform der -in letsencrypt.p7c -print_certs -outform pem -out letsencrypt.pem
