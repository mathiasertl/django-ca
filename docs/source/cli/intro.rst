######################
Command-line interface
######################

**django-ca** provides a complete command-line interface for all functionality. It is implemented as
subcommands of Django's :command:`manage.py` script. You can use it for all certificate management operations,
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
       edit_ca
       generate_crls
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
========================= ===============================================================

.. _subjects_on_cli:

****************************
Subjects on the command-line
****************************

.. WARNING::

   The support for RFC 4514 was added in ``django-ca==1.27`` and until ``django-ca==2.0``, the default is
   still an older format that is similar to how the command-line of ``openssl`` parses subjects. If you
   upgrade from an older version, please refer to the :ref:`migration information
   <update_126_rfc4514_subjects>`.

Subjects passed on the command-line (when creating a certificate authority or signing a certificate) use an
`RFC 4514 <https://datatracker.ietf.org/doc/html/rfc4514>`_-compatible format, with support for additional
key names.

.. NOTE::

   `RFC 4514 <https://datatracker.ietf.org/doc/html/rfc4514>`_ defines that elements shall be parsed in
   *reverse* order, similar to how some LDAP applications show subjects. Since the rest of the world displays
   subjects in the order as they appear in the certificate, **django-ca** does so as well.


Subject attributes are comma-separated, keys can be any value specified in RFC 4514. The following shows how
to create a certificate authority with a country, organization and common name in the subject:

.. code-block:: console

   $ python manage.py init_ca \
   >     NameOfCA C=AT,O=MyOrg,CN=ca.example.com

... but you can also use more special fields named in :py:attr:`~django_ca.constants.NAME_OID_NAMES`, e.g. a
more verbose common name and an email address:

.. code-block:: console

   $ python manage.py init_ca \
   >     NameOfCA C=AT,O=MyOrg,commonName=ca.example.com,emailAddress=admin@ca.example.com

As defined in RFC 4514, you can also use dotted strings to name arbitrary attributes. This example uses the
RFC 4514 defined key ``C`` for ``countryName``, the long format ``organizationName`` from
:py:attr:`~django_ca.constants.NAME_OID_NAMES` and the dotted string for ``commonName`` (but *any* other
valid dotted string could be used as well):

.. code-block:: console

   $ python manage.py init_ca \
   >     NameOfCA C=AT,organizationName=MyOrg,2.5.4.3=ca.example.com


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
``dirname``    An LDAP-style directory name, e.g. ``C=AT,L=Vienna,CN=example.at``.
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
