#####################################
Command-line interface - introduction
#####################################

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

For example, to get a list of signed certificates, give::

   $ python manage.py list_certs
   49:BC:F2:FE:FA:31:03:B6:E0:CC:3D:16:93:4E:2D:B0:8A:D2:C5:87 - localhost (expires: 2019-04-18)
   5A:1B:A2:63:A1:E4:D8:D1:4D:82:60:46:D3:8F:E0:C3:A5:B3:E4:89 - host1.example.com (expires: 2019-04-18)
   ...

.. NOTE:: Consider :ref:`creating a bash script <manage_py_shortcut>` to easily access your manage.py script.

*****************************
Overview of existing commands
*****************************

``manage.py`` subcommands for :doc:`certificate authority management <cli/cas>`:

===================== ===============================================================
Command               Description
===================== ===============================================================
dump_ca               Write the CA certificate to a file.
edit_ca               Edit an existing certificate authority.
import_ca             Import an existing certificate authority.
init_ca               Create a new certificate authority.
list_cas              List currently configured certificate authorities.
view_ca               View details of a certificate authority.
===================== ===============================================================

``manage.py`` subcommands for :doc:`certificate management <cli/certs>`:

===================== ===============================================================
Command               Description
===================== ===============================================================
cert_watchers         Add/remove addresses to be notified of an expiring certificate.
dump_cert             Dump a certificate to a file.
import_cert           Import an existing certificate.
list_certs            List all certificates.
notify_expiring_certs Send notifications about expiring certificates to watchers.
revoke_cert           Revoke a certificate.
sign_cert             Sign a certificate.
view_cert             View a certificate.
===================== ===============================================================

Miscellaneous ``manage.py`` subcommands (see :doc:`documentation <cli/various>`):

===================== ===============================================================
Command               Description
===================== ===============================================================
dump_crl              Write the certificate revocation list (CRL), see :doc:`crl`.
dump_ocsp_index       Write an OCSP index file, see :doc:`ocsp`.
===================== ===============================================================
