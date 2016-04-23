Custom manage.py commands
=========================

You can run your entire CA from the console without any webinterface at all,
using Djangos ``manage.py`` script. In case you also run a webinterface, this
will of course act with the same settings, database and CA certificates.

In general, run ``manage.py`` without any parameters for available subcommands::

   $ python manage.py

   ...
   [django_ca]
       cert_watchers
       dump_cert
       dump_crl
       ...

.. WARNING:: Remember to use the virtualenv if you use **django-ca** :ref:`as a
   standalone project <as-standalone>`.

Execute ``manage.py <subcommand> -h`` to get help on the subcommand. Here is an
overview of all subcommands provided by **django-ca**:

===================== ===============================================================
Command               Description
===================== ===============================================================
cert_watchers         Add/remove addresses to be notified of an expiring certificate.
dump_cert             Dump a certificate to a file.
dump_crl              Write the certificate revocation list (CRL).
dump_ocsp_index       Write an OCSP index file.
list_certs            List all certificates.
notify_expiring_certs Send notifications about expiring certificates to watchers.
revoke_cert           Revoke a certificate.
sign_cert             Sign a certificate.
view_cert             View a certificate.
===================== ===============================================================

The following commands are used to manage certificate autorities:

===================== ===============================================================
Command               Description
===================== ===============================================================
init_ca               Create a new certificate authority.
list_cas              List currently configured certificate authorities.
edit_ca               Edit an existing certificate authority.
view_ca               View details of a certificate authority.
dump_ca               Write the CA certificate to a file.
===================== ===============================================================
