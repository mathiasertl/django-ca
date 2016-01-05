Run a OCSP responder
====================

Hosting an OCSP service is the second method (besides :doc:`CRLs <crl`) of
letting a client know if a certificate has been revoked.

To run an OCSP responder, you first need a certificate with some special
properties. Luckily, **django-ca** has a profile predefined for you::

   openssl genrsa -out ocsp.example.com.key 4096
   openssl req -new -key ocsp.example.com.key -out ocsp.example.com.csr -utf8 \
      -batch -subj '/CN=ocsp.example.com'
   python manage.py sign_cert --csr=ocsp.example.com.csr \
      --out=ocsp.example.com.pem --cn=ocsp.example.com --ocsp

Next, you'll need an OCSP index file::

   python manage.py dump_ocsp_index ocsp.index

OpenSSL itself allows you to run an OCSP responder with this command::

   openssl ocsp -index ocsp.index -port 8888 -rsigner ocsp.example.com.pem \
      -rkey ocsp.example.com.key -CA files/ca.crt -text


A Certificate Revokation List (CRL) contains all revoked certificates your
certificate authority that are served via HTTP and added to your certificates
via the ``crlDistributionPoints`` x509 extension. Having a CRL is completely
optional (e.g. `Let's Encrypt <https://letsencrypt.org/>`_ certificates don't
have one).

.. NOTE:: CRLs are usually hosted via HTTP, **not** HTTPS. CRLs are always
   signed, so hosting them via HTTP is not a security vulnerability. On the
   other hand, you cannot verify the the certificate used when fetching the CRL
   anyway, since you would need the CRL for that.

You can generate the CRL with the ``manage.py dump_crl`` command. How and where
to host that file is entirely up to you. If you run a Django project with a
webserver already, one possibility is to dump it to a directory named by the
``STATIC_DIRS`` setting.

To make signed certificates include the OCSP responder URL, simply configure
the ``CA_OCSP`` setting (see :doc:`settings`)::

   CA_OCSP = "http://ocsp.example.com"
