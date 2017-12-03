######################
Command-line interface
######################

**django-ca** provides a complete command-line interface for all functionality. It is implemented
as subcommands of Djangos ``manage.py`` script. You can use it for all certificate management
operations, and :doc:`/cli/cas` is only possible via the command-line interface for security
reasons.

In general, run ``manage.py`` without any parameters for available subcommands::

   $ python manage.py

   ...
   [django_ca]
       cert_watchers
       dump_cert
       dump_crl
       ...

Various tasks for the command-line interface are documented in individual documents:

.. toctree::
   :maxdepth: 1

   CA management </cli/cas>
   Certificate management </cli/certs>
   Miscellaneous commands </cli/misc>

.. NOTE:: Consider :ref:`creating a bash script <manage_py_shortcut>` to easily access your manage.py script.

**************************
Index of existing commands
**************************

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
