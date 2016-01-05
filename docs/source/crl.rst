Host a Certificate Revokation List (CRL)
========================================

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

To have signed certificates use the CRL, simply configure the
``CA_CRL_DISTRIBUTION_POINTS`` setting (see :doc:`settings`).
