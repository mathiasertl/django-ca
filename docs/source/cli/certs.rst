#####################
Managing certificates
#####################

All certificate operations can be done via the command line. You do not have to use this interface, all
functionality is also available via the :doc:`/web_interface`, if it has access to the private key of the
certificate authority.

*****************
Index of commands
*****************

To manage certificate, use the following :command:`manage.py` commands:

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

Like all :command:`manage.py` subcommands, you can run ``manage.py <subcomand> -h`` to get a list of available
parameters.

.. _cli_sign_certs:

********************
Signing certificates
********************

Signing certificates is done using :command:`manage.py sign_cert`. The only requirements are that you provide
either a full subject and/or one or more alternative names. Obviously, you also need to create at least one
certificate authority first (:doc:`documentation </cli/cas>`).

Like any good certificate authority, **django-ca** never handles private keys of signed certificates. Instead,
you sign certificates from a Certificate Signing Request (CSR) that you generate from the private key. Using
the OpenSSL command-line tools, you can create a CSR *on the host that should use the certificate*:

.. code-block:: console

   $ openssl genrsa -out example.key 4096
   $ openssl req -new -key example.key -out example.csr -utf8

Next, simply copy the CSR file (``example.csr`` in the above example) to the host where you installed
**django-ca**. You can now create a signed certificate using:

.. code-block:: console

   $ python manage.py sign_cert --alt example.com --csr example.csr --out example.pub

If you have defined multiple CAs, you also have to name the CA:

.. code-block:: console

   $ python manage.py list_cas
   4E:1E:2A:29:F9:4C:45:CF:12:2F:2B:17:9E:BF:D4:80:29:C6:37:C7 - Root CA
   32:BE:A9:E8:7E:21:BF:3E:E9:A1:F3:F9:E4:06:14:B4:C4:9D:B2:6C - Child CA
   $ python manage.py sign_cert --ca 32:BE:A9 --alt example.com --csr example.csr --out example.pub

Profiles
========

Use :doc:`profiles </profiles>` to configure how your certificates can be used. You can set a profile by
simply passing it via the command line. For example, to use the **client** profile:

.. code-block:: console

   $ python manage.py sign_cert --alt example.com --csr example.csr --out example.pub --client

Please see :doc:`the documentation </profiles>` the documentation on what profiles are available and how you
can update existing profiles and even add new ones.

Subject and alternative names
=============================

The Certificate's Subject (that is, it's CommonName) and the names given in the ``SubjectAlternativeName``
extension define where the certificate is valid.

The CommonName is usually added to the ``SubjectAlternativeName`` extension as well and vice versa. This means
that these two will give the same CommonName and ``subjectAltName``:

.. code-block:: console

   $ python manage.py sign_cert --subject /C=AT/.../CN=example.com
   $ python manage.py sign_cert --alt example.com

A given CommonName is only added to the ``SubjectAlternativeName`` extension if it is a valid :ref:`name
<names_on_cli>`. If you give multiple names via ``--alt`` but no CommonName, the first one will be used as
CommonName. Names passed via ``--alt`` are parsed as :ref:`names <names_on_cli>`, so you can also use e.g.:

.. code-block:: console

   $ python manage.py sign_cert --alt IP:127.0.0.1

You can also disable adding the CommonName as ``subjectAlternativeName``:

.. code-block:: console

   $ python manage.py sign_cert --cn-not-in-san --subject /C=AT/.../CN=example.com --alt=example.net

... this will only have "example.net" but not example.com as ``subjectAlternativeName``.

Advanced subject alternative names
----------------------------------

You can add ``OtherName`` values to ``SubjectAlternativeName`` via the same format used by OpenSSL described
in :manpage:`ASN1_GENERATE_NCONF(3SSL)`:

.. code-block:: console

   $ python manage.py sign_cert --subject /CN=example.com --alt="otherName:1.3.6.1.4.1.311.20.2.3;UTF8:dummy@domain.tld"

Note that currently only UTF8 strings are supported.

Using profiles
==============

Certificates have extensions that define certain aspects of how/why/where/when a certificate can be used. Some
extensions are added based on how the Certificate Authority is configured, e.g. CRL/OCSP URLs. Extensions that
define for what purposes are a certificate can be used can be configured on a per-certificate basis.

The easiest way is to use profiles that define what extensions are added to any certificate. **django-ca**
adds these predefined profiles:

============== ==========================================================================================
Name           Purpose
============== ==========================================================================================
``client``     Allows the certificate to be used on the client-side of a TLS connection.
``server``     Allows the certificate to be used on the client- and server-side of a connections.
``enduser``    Allows client authentication and code and email signing.
``webserver``  Allows only the server-side of a TLS connection, it can't be used as a client certificate.
``ocsp``       Allows the certificate to be used for signing OCSP responses.
============== ==========================================================================================

You can add and modify profiles using the :ref:`CA_PROFILES <settings-ca-profiles>` setting. The default
profile is configured by the :ref:`CA_DEFAULT_PROFILE <settings-ca-default-profile>` setting.

Signature hash algorithms
=========================

When using a certificate authority based on an RSA and Elliptic Curve (EC) private key, you can override the
signature hash algorithm used for signing the certificate with the ``--algorithm`` parameter. By default, the
hash algorithm that was used to sign the certificate authority will be used. See
:py:attr:`~django_ca.constants.HASH_ALGORITHM_NAMES` for a list of supported hash algorithms.

For example, to sign a certificate using SHA-384:

.. code-block:: console

   $ python manage.py sign_cert --algorithm=SHA-384 ...

Certificate authorities that use an Ed448- or Ed25519-based private key, do not use a hash algorithm when
signing certificates, so an error will be raised if you pass the ``--algorithm`` option with such certificate
authorities.

.. _override-extensions:

Override extensions
===================

You can override some extensions using command-line parameters. Currently, this includes the Key Usage,
Extended Key Usage, OCSPNoCheck and TLSFeature extensions:

.. code-block:: console

   $ python manage.py sign_cert \
      --key-usage keyCertSign \
      --extended-key-usage serverAuth clientAuth \
      --extended-key-usage-critical \
      --tls-feature status_request \
      ...

For more information on these extensions, their meaning and typical values, see :doc:`/extensions`.

*******************
Revoke certificates
*******************

To revoke a certificate, use:

.. code-block:: console

   $ python manage.py list_certs
   49:BC:F2:FE:FA:31:03:B6:E0:CC:3D:16:93:4E:2D:B0:8A:D2:C5:87 - localhost (expires: 2019-04-18)
   ...
   $ python manage.py revoke_cert 49:BC:F2:FE:FA:31:03:B6:E0:CC:3D:16:93:4E:2D:B0:8A:D2:C5:87

*********************
Expiring certificates
*********************

You can add email addresses to be notified of expiring certificates using the ``--watch`` parameter:

.. code-block:: console

   $ python manage.py --sign-cert --watch user@example.com --watch user@example.net ...

Or modify to add/remove watchers later:

.. code-block:: console

   $ python manage.py list_certs
   49:BC:F2:FE:FA:31:03:B6:E0:CC:3D:16:93:4E:2D:B0:8A:D2:C5:87 - localhost (expires: 2019-04-18)
   ...
   $ python manage.py cert_watchers -a add@example.com -r user@example.net 49:BC:F2
