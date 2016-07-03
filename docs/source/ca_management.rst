################################
Certificate authority management
################################

**django-ca** supports managing multiple certificate authorities as well as child certificate
authorities.

The only way to create certificate authorities is via the :doc:`command-line interface
<cli_interface>`.  It is obviously most important that the private keys of the certificate
authorities are never exposed to any attacker, and any web interface would pose an unnecessary
risk.

For the same reason, the private key of a certificate authority is stored on the filesystem and not
in the database. The initial location of the private key is configured by the :ref:`CA_DIR setting
<settings-ca-dir>`. This also means that you can run your **django-ca** on two hosts, where one
host has the private key and only uses the command line, and one with the webinterface that can
still be used to revoke certificates.

To manage certificate authorities, use the following `manage.py` commands:

======== ======================================================
Command  Description
======== ======================================================
init_ca  Create a new certificate authority.
list_cas List all currently configured certificate authorities.
edit_ca  Edit a certificate authority.
view_ca  View details of a certificate authority.
dump_ca  Write the CA certificate to a file.
======== ======================================================

Various details of the certificate authority, mostly the x509 extensions used
when signing a certificate, can also be managed via the webinterface.

Here is a shell session that illustrates the respective manage.py commands:

.. code-block:: console

   $ python manage.py init_ca --pathlen=2
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

Intermediate CAs are created, just like normal CAs, using ``manage.py init_ca``. For intermediate
CAs to be valid, CAs however must have a correct ``pathlen`` x509 extension. Its value is an
integer describing how many levels of intermediate CAs a CA may have. A ``pathlen`` of "0" means
that a CA cannot have any intermediate CAs, if it is not present, a CA may have an infinite number
of intermediate CAs.

.. NOTE:: **django-ca** by default sets a ``pathlen`` of "0", as it aims to be secure by default.
   The ``pathlen`` attribute cannot be changed in hindsight (not without resigning the CA). If you
   plan to create intermediate CAs, you have to consider this when creating the root CA.

So for example, if you want two levels of intermediate CAs, , you'd need the following ``pathlen``
values (the ``pathlen`` value is the minimum value, it could always be a larger number):

===== ==================== ======= ========================================================
index CA                   pathlen description
===== ==================== ======= ========================================================
1     example.com          2       Your root CA.
2     sub1.example.com     1       Your first intermediate CA, a sub-CA from (1).
3     sub2.example.com     0       A second intermediate CA, also a sub-CA from (1).
4     sub.sub1.example.com 0       An intermediate CA of (2).
===== ==================== ======= ========================================================

If in the above example, CA (1) had ``pathlen`` of "1" or CA (2) had a ``pathlen`` of "0", CA (4)
would no longer be a valid CA.

By default, **django-ca** sets a ``pathlen`` of 0, so CAs will not be able to have any intermediate
CAs. You can configure the value by passing ``--pathlen`` to ``init_ca``:

.. code-block:: console

   $ python manage.py init_ca --pathlen=2 ...

When creating a sub-ca, you must name its parent using the ``--parent`` parameter:

.. code-block:: console

   $ python manage.py list_cas
   BD:5B:AB:5B:A2:1C:49:0D:9A:B2:AA:BC:68:ED:ED:7D - Root CA
   $ python manage.py init_ca --parent=BD:5B:AB:5B ...

.. NOTE:: Just like throughout the system, you can always just give the start of the serial, as
   long as it still is a unique identifier for the CA.
