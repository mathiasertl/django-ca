######################
Command-line interface
######################

**django-ca** provides a complete command-line interface for all functionality. It is implemented as
subcommands of Djangos :command:`manage.py` script. You can use it for all certificate management operations,
and :doc:`/cli/cas` is only possible via the command-line interface for security reasons.

.. NOTE::

   How you invoke :command:`manage.py` differs depending on how you installed django-ca. Refer to the
   installation guide you followed for further instructions.

In general, run :command:`manage.py` without any parameters for available subcommands:

.. code-block:: console

   $ python manage.py

   ...
   [django_ca]
       cert_watchers
       dump_cert
       dump_crl
       ...

Creating Certificate Authorities and managing Certificates is documented on individual pages:

.. toctree::
   :maxdepth: 1

   CA management </cli/cas>
   Certificate management </cli/certs>

**************************
Index of existing commands
**************************

:command:`manage.py` subcommands for :doc:`certificate authority management </cli/cas>`:

========================= ===============================================================
Command                   Description
========================= ===============================================================
``dump_ca``               Write the CA certificate to a file.
``edit_ca``               Edit an existing certificate authority.
``import_ca``             Import an existing certificate authority.
``init_ca``               Create a new certificate authority.
``list_cas``              List currently configured certificate authorities.
``view_ca``               View details of a certificate authority.
========================= ===============================================================

:command:`manage.py` subcommands for :doc:`certificate management </cli/certs>`:

========================= ===============================================================
Command                   Description
========================= ===============================================================
``cert_watchers``         Add/remove addresses to be notified of an expiring certificate.
``dump_cert``             Dump a certificate to a file.
``import_cert``           Import an existing certificate.
``list_certs``            List all certificates.
``notify_expiring_certs`` Send notifications about expiring certificates to watchers.
``revoke_cert``           Revoke a certificate.
``sign_cert``             Sign a certificate.
``view_cert``             View a certificate.
========================= ===============================================================

Miscellaneous :command:`manage.py` subcommands:

========================= ===============================================================
Command                   Description
========================= ===============================================================
``dump_crl``              Write the certificate revocation list (CRL), see :doc:`/crl`.
``dump_ocsp_index``       Write an OCSP index file, see :doc:`/ocsp`.
========================= ===============================================================

.. _names_on_cli:

*************************
Names on the command-line
*************************

The most common use case for certificates is to issue certificates for domains. For example, a certificate for
"example.com" is valid for exactly that domain and no other. But certificates can be valid for various other
names as well, e.g. email addresses or URLs. Those names also occur in other places, like in the
:ref:`name_constraints` extension for CAs.

On the command-line, **django-ca** will do its best to guess what you want. This example would issue a
certificate valid for one domain and and one email address:

.. code-block:: console

   $ python manage.py sign_cert --alt example.com --alt user@example.net ...

If the name you're giving might be ambiguous or you just want to make sure that the value is interpreted
correctly, you can always use a prefix to force a particular type. This is equivalent to the above example:

.. code-block:: console

   $ python manage.py sign_cert --alt DNS:example.com --alt email:user@example.net ...

Valid prefixes right now are:

============== =============================================================================
Prefix         Meaning
============== =============================================================================
``DNS``        A DNS name, the most common use case.
``email``      An email address (e.g. used when using S/MIME to sign emails).
``dirname``    An LDAP-style directory name, e.g. ``/C=AT/L=Vienna/CN=example.at``.
``URI``        A URI, e.g. https://example.com.
``IP``         An IP address, both IPv4 and IPv6 are supported.
``RID``        A "Registered ID". No real-world examples are known, you're on your own.
``otherName``  Anything not covered in the above values. Same restrictions as for RID apply.
============== =============================================================================

Wildcard names
==============

In some cases you might want to use a wildcard in DNS names. The most common use cases are "wildcard
certificates", which are valid for all given subdomains. Creating such certificates is simple:

.. code-block:: console

   $ python manage.py sign_cert --alt *.example.com ...

IP addresses
============

Both IPv4 and IPv6 addresses are supported, e.g. this certificate is valid for ``localhost`` on both IPv4 and
IPv6:

.. code-block:: console

   python manage.py sign_cert --alt ::1 --alt 127.0.0.1 ...
