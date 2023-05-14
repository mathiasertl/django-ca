################################
Certificate authority management
################################

.. highlight:: console

**django-ca** supports managing multiple certificate authorities as well as child certificate
authorities.

The :doc:`command-line interface </cli/intro>` is the only way to create certificate authorities.  It is
obviously most important that the private keys are never exposed to any attacker, and any web interface would
pose an unnecessary risk. Some details, like the x509 extensions used for signing certificates, can be
configured using the web interface.

For the same reason, the private key of a certificate authority is stored on the file system and not in the
database. The initial location of the private key is configured by the :ref:`CA_DIR setting
<settings-ca-dir>`. This also means that you can run your **django-ca** on two hosts, where one host has the
private key and only uses the command line, and one with the web interface that can still be used to revoke
certificates.

*****************
Index of commands
*****************

To manage certificate authorities, use the following :command:`manage.py` commands:

============== ======================================================
Command        Description
============== ======================================================
``dump_ca``    Write the CA certificate to a file.
``edit_ca``    Edit a certificate authority.
``import_ca``  Import an existing certificate authority.
``init_ca``    Create a new certificate authority.
``list_cas``   List all currently configured certificate authorities.
``view_ca``    View details of a certificate authority.
============== ======================================================

Like all :command:`manage.py` subcommands, you can run ``manage.py <subcomand> -h`` to get a list of available
parameters.

***************
Create a new CA
***************

There are many options when creating a new certificate authority, but the defaults are carefully chosen to be
secure. To create a simple setup with a root certificate authority and an intermediate certificate authority
that has ACMEv2 enabled, simply use:

.. code-block:: console

   $ python manage.py init_ca --path-length=1 Root /CN=Root
   $ python manage.py init_ca --parent=Root --acme-enable Intermediate /CN=Intermediate

.. NOTE::

   How you invoke :command:`manage.py` differs depending on how you installed django-ca. Refer to the
   installation guide you followed for further instructions and complete examples.

You should be very careful when creating a new certificate authority, especially if it is used by a large
number of clients. If you make a mistake here, it could make your CA unusable and you have to redistribute new
public keys to all clients, which is usually a lot of work.

Please think carefully about how you want to run your CA: Do you want intermediate CAs? Do you want to use
CRLs and/or run an OCSP responder?

Private key parameters
======================

The private key generated for your certificate authority may vary based on key type, key size and elliptic
curve used.

Key type
--------

The type of private key can be configured with the ``--key-type`` parameter. Currently supported values are
``RSA`` (the default), ``EC`` (for elliptic curve cryptography based keys), ``Ed448``, and ``Ed25519``.
``DSA`` is also supported but the use is discouraged.

Key size
--------

For ``RSA`` and ``DSA`` keys, you can specify the size of the private key using the ``--key-size`` option.
The value must be an integer and a power of two. ``2048`` or ``4096`` are reasonable values.

The default is specified using the :ref:`settings-ca-default-key-size` setting, the minimum value is set by
the :ref:`settings-ca-min-key-size` setting.

Elliptic curve
--------------

When generating an ``EC`` (elliptic curve) private key, you can chose the elliptic curve used with the
``--elliptic-curve`` parameter. The default curve is configured using the
:ref:`settings-ca-default-elliptic-curve` setting.

The supported elliptic curves are the curves found in the :py:attr:`~django_ca.constants.ELLIPTIC_CURVE_TYPES`
constant. Please see the `cryptography information on elliptic curves
<https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/>`_ for more information on each curve.

Hostname
========

Running a CA with an OCSP responder or CRLs for certificate validation requires a web server providing HTTP.
Please configure :ref:`CA_DEFAULT_HOSTNAME <settings-ca-default-hostname>` accordingly. You can always
override that setting by passing manual URLs when creating a new CA.

.. _signature_hash_algorithms:

Signature hash algorithm
========================

The hash algorithm used for signing the public key can be configured using the ``--algorithm`` parameter.

For root certificate authorities, the default is configured via the
:ref:`settings-ca-default-signature-hash-algorithm` setting for RSA and Elliptic Curve (EC) keys, and via the
:ref:`settings-ca-default-dsa-signature-hash-algorithm` setting for DSA keys. Intermediate certificate
authorities will use the same hash algorithm as their parent by default.

The supported signature hash algorithms are the hash algorithms in the
:py:attr:`~django_ca.constants.HASH_ALGORITHM_NAMES` constant. For example, to use SHA-384 as signature hash
algorithm:

.. code-block:: console

   $ python manage.py init_ca --algorithm=SHA-384 ...

Ed448 and and Ed25519 keys do not use a signature hash algorithm and an error will be raised if you pass the
``--algorithm`` option with these key types.

CRL URLs
========

Certificate Revocation Lists (CRLs) are signed files that contain a list of all revoked certificates.
Certificates (including those for CAs) can contain pointers to CRLs, usually a single URL, in the CRL
Distribution Points extension. Clients that support this extension can query the URL and refuse to establish a
connection if the certificate is revoked.

Since a CRL has to be signed by the issuing CA, root CAs cannot sensibly contain a CRL: You could only revoke
the root CA with it, and it would have to be signed by the (compromised) root CA.

If you have correctly configured :ref:`CA_DEFAULT_HOSTNAME <settings-ca-default-hostname>`, you can use CRL
URLs out of the box. You can also embed custom URLs in certificates, please see :doc:`/crl` for more
information.

OCSP responder
==============

The `Online Certificate Status Protocol <https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol>`_
or OCSP is a service (called "OCSP responder") run by a certificate authority that allows clients to query for
revoked certificates. It is an improvement over CRLs particularly for larger CAs because a full CRL can grow
quite big.

The same restrictions as for CRLs apply: You cannot add a OCSP URL to a root CA, it runs via HTTP (not HTTPS)
and if you decide to add such URLs, you also have to actually run that service, or clients will refuse to
connect.

If you have correctly configured :ref:`CA_DEFAULT_HOSTNAME <settings-ca-default-hostname>`, you can use an
OCSP responder *almost* out of the box, the only thing you have to do is *regularly* create OCSP responder
keys:

.. code-block:: console

   $ python manage.py regenerate_ocsp_keys

Extensions
==========

Basic Constraints
-----------------

The Basic Constraints extension (`RFC 5280, section 4.2.1.9
<https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9>`_) is always added as a critical extension.
For certificate authorities, the optional `path length` attribute specifies how many levels of intermediate
certificate authorities can exist below itself. If the attribute is *not* present, the number is unlimited.

**django-ca** sets a path length of ``0`` by default. You can set a different value using ``--path-length``::

    $ python manage.py init_ca --path-length 3 ...

If you do not want to set a path length attribute, use ``--no-path-length``::

    $ python manage.py init_ca --no-path-length ...

Note that for a valid setup, the attributes in all intermediate CAs must be correct. Here is a typical
example:

.. code-block:: none

   root   # path length: 2
   |- child_A  # path length: 1
      |- child_A.1  # path length: 0
   |- child_B  # path length" 0

In this example, `root` and `child_A` can have intermediate CAs, while `child_B` and `child_A.1` can not.

Certificate Policies
--------------------

To add the Certificate Policies extension (`RFC 5280, section 4.2.1.4
<https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.4>`_) to a certificate authority, use the
``--policy-identifier`` option to add a policy with the given OID::

   $ python manage.py init_ca --policy-identifier=1.2.3 ...

The special value ``anyPolicy`` is recognized as an alias for the OID ``2.5.29.32.0``. To add a certification
practice statement (CPS) and/or user notices, use::

   $ python manage.py init_ca \
   >     --policy-identifier=anyPolicy \
   >     --certification-practice-statement=https://example.com/cps/ \
   >     --user-notice="Example user notice text" \
   >     ...

To add multiple policies, repeat the ``--policy-identifier`` option. The options for CPS and user notices will
be added to the last named policy::

   $ python manage.py init_ca \
   >     --policy-identifier=1.2.3 \
   >     --certification-practice-statement=https://example.com/cps-for-1.2.3/ \
   >     --policy-identifier=1.2.4 \
   >     --user-notice="User notice for 1.2.4" \
   >     ...

Adding notice references via the command line is not supported.

.. _name_constraints:

Name Constraints
----------------

The Name Constraints extension (`RFC 5280, section 4.2.1.10
<https://tools.ietf.org/html/rfc5280#section-4.2.1.10>`_ allows you to create CAs that are limited to
issuing certificates for a particular set of names. The parsing of this syntax is quite complex, see e.g.
`this blog post
<https://www.sysadmins.lv/blog-en/x509-name-constraints-certificate-extension-all-you-should-know.aspx>`_ for
a good explanation.

.. WARNING::

   This extension is marked as "critical". Any client that does not understand this extension will refuse a
   connection.

To add name constraints to a CA, use the ``--permit-name`` and ``--exclude-name``, both of which can be given
multiple times. Values are any valid name, see :ref:`names_on_cli` for detailed documentation::

   $ python manage.py init_ca --permit-name DNS:example.com --exclude-name DNS:example.net ...

This will restrict the CA to issuing certificates for .com and .net subdomains, except for evil.com, which
obviously should never have a certificate (evil.net is good, though).

Examples
========

Here is a shell session that illustrates the respective :command:`manage.py` commands:

.. code-block:: console

   $ python manage.py init_ca --path-length=2
   >     --crl-url=http://ca.example.com/crl \
   >     --ocsp-url=http://ocsp.ca.example.com \
   >     --issuer-url=http://ca.example.com/ca.crt \
   >     TestCA /C=AT/L=Vienna/L=Vienna/O=Example/OU=ExampleUnit/CN=ca.example.com
   $ python manage.py list_cas
   BD:5B:AB:5B:A2:1C:49:0D:9A:B2:AA:BC:68:ED:ED:7D - TestCA

   $ python manage.py view_ca BD:5B:AB:5B:A2
   ...
   * OCSP URL: http://ocsp.ca.example.com
   $ python manage.py edit_ca --ocsp-url=http://new-ocsp.ca.example.com \
   >     BD:5B:AB:5B:A2
   $ python manage.py view_ca BD:5B:AB:5B:A2
   ...
   * OCSP URL: http://new-ocsp.ca.example.com

Note that you can just use the start of a serial to identify the CA, as long as
that still uniquely identifies the CA.

***********************
Create intermediate CAs
***********************

Intermediate CAs are created, just like normal CAs, using :command:`manage.py init_ca`. For intermediate CAs
to be valid, CAs however must have a correct ``path length`` in the BasicConstraints x509 extension. Its value
is an integer describing how many levels of intermediate CAs a CA may have. A ``path length`` of "0" means
that a CA cannot have any intermediate CAs, if it is not present, a CA may have an infinite number of
intermediate CAs.

.. NOTE:: **django-ca** by default sets a ``path length`` of "0", as it aims to be secure by default.
   The ``path length`` attribute cannot be changed in hindsight (not without resigning the CA). If you
   plan to create intermediate CAs, you have to consider this when creating the root CA.

So for example, if you want two levels of intermediate CAs, , you'd need the following ``path length``
values (the ``path length`` value is the minimum value, it could always be a larger number):

===== ==================== =============== ========================================================
index CA                   ``path length`` description
===== ==================== =============== ========================================================
1     example.com          2               Your root CA.
2     sub1.example.com     1               Your first intermediate CA, a sub-CA from (1).
3     sub2.example.com     0               A second intermediate CA, also a sub-CA from (1).
4     sub.sub1.example.com 0               An intermediate CA of (2).
===== ==================== =============== ========================================================

If in the above example, CA (1) had ``path length`` of "1" or CA (2) had a ``path length`` of "0", CA (4)
would no longer be a valid CA.

By default, **django-ca** sets a ``path length`` of 0, so CAs will not be able to have any intermediate
CAs. You can configure the value by passing ``--path-length`` to ``init_ca``:

.. code-block:: console

   $ python manage.py init_ca --path-length=2 ...

When creating a sub-ca, you must name its parent using the ``--parent`` parameter:

.. code-block:: console

   $ python manage.py list_cas
   BD:5B:AB:5B:A2:1C:49:0D:9A:B2:AA:BC:68:ED:ED:7D - Root CA
   $ python manage.py init_ca --parent=BD:5B:AB:5B ...

.. NOTE:: Just like throughout the system, you can always just give the start of the serial, as
   long as it still is a unique identifier for the CA.
