Command-line interface
======================

**django-ca** provides a complete command-line interface for all functionality. It is implemented
as subcommands of Djangos ``manage.py`` script. You can use it for all certificate management
operations, and :doc:`ca_management` is only possible via the command-line interface for security
reasons.

In general, run ``manage.py`` without any parameters for available subcommands::

   $ python manage.py

   ...
   [django_ca]
       cert_watchers
       dump_cert
       dump_crl
       ...

.. WARNING:: Remember to use the virtualenv if you installed **django-ca** in one.


Execute ``manage.py <subcommand> -h`` to get help on the subcommand.

``manage.py`` subcommands for :doc:`certificate authority management <ca_management>`:

===================== ===============================================================
Command               Description
===================== ===============================================================
dump_ca               Write the CA certificate to a file.
edit_ca               Edit an existing certificate authority.
init_ca               Create a new certificate authority.
list_cas              List currently configured certificate authorities.
view_ca               View details of a certificate authority.
===================== ===============================================================

``manage.py`` subcommands for certificate management:

===================== ===============================================================
Command               Description
===================== ===============================================================
cert_watchers         Add/remove addresses to be notified of an expiring certificate.
dump_cert             Dump a certificate to a file.
list_certs            List all certificates.
notify_expiring_certs Send notifications about expiring certificates to watchers.
revoke_cert           Revoke a certificate.
sign_cert             Sign a certificate.
view_cert             View a certificate.
===================== ===============================================================

Miscellaneous ``manage.py`` subcommands:

===================== ===============================================================
Command               Description
===================== ===============================================================
dump_crl              Write the certificate revocation list (CRL), see :doc:`crl`.
dump_ocsp_index       Write an OCSP index file, see :doc:`ocsp`.
===================== ===============================================================

