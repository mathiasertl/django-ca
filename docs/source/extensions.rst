###############
x509 extensions
###############

This page provides a list of supported TLS extensions. They can be selected in
the admin interface or via the command line. Please see
:ref:`override-extensions` for more information on how to set these extensions
in the command line.

.. _extension-key-usage:

********
KeyUsage
********

The KeyUsage extension defines the basic purpose of the certificate. It is defined in `RFC5280, section
4.2.1.3 <https://tools.ietf.org/html/rfc5280#section-4.2.1.3>`_. The extension is usually defined as critical.

================= ==========================================================================================
Name              Used for
================= ==========================================================================================
cRLSign
dataEncipherment  email encryption
decipherOnly
digitalSignature  TLS connections (client and server), email and code signing, OCSP responder
encipherOnly
keyAgreement      TLS server connections
keyCertSign
keyEncipherment   TLS server connections, email encryption, OCSP responder
nonRepudiation    OCSP responder
================= ==========================================================================================

Currently, the default profiles (see :ref:`CA_PROFILES <settings-ca-profiles>` setting) use these values:

================= ========== ========== ============= =========== ========
value             ``client`` ``server`` ``webserver`` ``enduser`` ``ocsp``
================= ========== ========== ============= =========== ========
cRLSign           ✗          ✗          ✗             ✗           ✗
dataEncipherment  ✗          ✗          ✗             ✓           ✗
decipherOnly      ✗          ✗          ✗             ✗           ✗
digitalSignature  ✓          ✓          ✓             ✓           ✓
encipherOnly      ✗          ✗          ✗             ✗           ✗
keyAgreement      ✗          ✓          ✓             ✗           ✗
keyCertSign       ✗          ✗          ✗             ✗           ✗
keyEncipherment   ✗          ✓          ✓             ✓           ✓
nonRepudiation    ✗          ✗          ✗             ✗           ✓
================= ========== ========== ============= =========== ========

.. _extension-extended-key-usage:

****************
ExtendedKeyUsage
****************

The ExtendedKeyUsage extension refines the KeyUsage extension and is defined in `RFC5280, section 4.2.1.12
<https://tools.ietf.org/html/rfc5280#section-4.2.1.12>`_. The extension is usually not defined as critical.

================= ==========================================================================================
Name              Used for
================= ==========================================================================================
serverAuth        TLS server connections
clientAuth        TLS client connections
codeSigning       Code signing
emailProtection   Email signing/encryption
timeStamping
OCSPSigning       Running an OCSP responder
smartcardLogon    Required for user certificates on smart cards for PKINIT logon on Windows
msKDC             Required for Domain Controller certificates to authorize them for PKINIT logon on Windows
================= ==========================================================================================

Currently, the default profiles (see :ref:`CA_PROFILES <settings-ca-profiles>` setting) use these values:

================= ========== ========== ============= =========== ========
value             ``client`` ``server`` ``webserver`` ``enduser`` ``ocsp``
================= ========== ========== ============= =========== ========
serverAuth        ✗          ✓          ✓             ✓           ✗
clientAuth        ✓          ✓          ✗             ✓           ✗
codeSigning       ✗          ✗          ✗             ✓           ✗
emailProtection   ✗          ✗          ✗             ✗           ✗
timeStamping      ✗          ✗          ✗             ✗           ✗
OCSPSigning       ✗          ✗          ✗             ✗           ✓
smartcardLogon    ✗          ✗          ✗             ✗           ✗
msKDC             ✗          ✗          ✗             ✗           ✗
================= ========== ========== ============= =========== ========

.. _extension-tls-feature:

**********
TLSFeature
**********

The ``TLSFeature`` extension is defined in `RFC7633 <https://tools.ietf.org/html/rfc7633>`_. This extension
should not be marked as critical.

================= ==========================================================================================
Name              Description
================= ==========================================================================================
status_request    TLS connections *must* include a stapled OCSP response, defined in
                  `RFC6066 <https://tools.ietf.org/html/rfc6066.html>`_. Also known as "OCSPMustStaple".
status_request_v2 Not commonly used, defined in `RFC6961 <https://tools.ietf.org/html/rfc6961.html>`_. Also
                  known as "MultipleCertStatusRequest".
================= ==========================================================================================

The use of this extension is currently discouraged. Current OCSP stapling implementation are still poor,
making this a dangerous extension.
