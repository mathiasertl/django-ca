############################
x509 extensions in other CAs
############################

This page documents the x509 extensions (e.g. for CRLs, etc.) set by other CAs.


*******************
authorityInfoAccess
*******************

In CA certificates
==================

================= =================================================================================
CA                Value
================= =================================================================================
Let's Encrypt     * OCSP - URI:http://isrg.trustid.ocsp.identrust.com
                  * CA Issuers - URI:http://apps.identrust.com/roots/dstrootcax3.p7c
StartSSL          (not present)
StartSSL Class 2  * OCSP - URI:http://ocsp.startssl.com/ca
                  * CA Issuers - URI:http://aia.startssl.com/certs/ca.crt
StartSSL Class 3  * OCSP - URI:http://ocsp.startssl.com
                  * CA Issuers - URI:http://aia.startssl.com/certs/ca.crt
GeoTrust Global
RapidSSL G3
Comodo
Comodo DV
GlobalSign
GlobalSign DV
================= =================================================================================


In signed certificates
======================

================ =================================================================================
CA               Value
================ =================================================================================
Let's Encrypt    * OCSP - URI:http://ocsp.int-x1.letsencrypt.org/
                 * CA Issuers - URI:http://cert.int-x1.letsencrypt.org
StartSSL Class 2 * OCSP - URI:http://ocsp.startssl.com/sub/class2/server/ca
                 * CA Issuers - URI:http://aia.startssl.com/certs/sub.class2.server.ca.crt
StartSSL Class 3 * OCSP - URI:http://ocsp.startssl.com
                 * CA Issuers - URI:http://aia.startssl.com/certs/sca.server3.crt
RapidSSL G3
Comodo DV
GlobalSign DV
================ =================================================================================

**********************
authorityKeyIdentifier
**********************

In CA certificates
==================

================ =================================================================================
CA               Value
================ =================================================================================
Let's Encrypt    keyid:C4:A7:B1:A4:7B:2C:71:FA:DB:E1:4B:90:75:FF:C4:15:60:85:89:10
StartSSL         keyid:4E:0B:EF:1A:A4:40:5B:A5:17:69:87:30:CA:34:68:43:D0:41:AE:F2
StartSSL Class 2 keyid:4E:0B:EF:1A:A4:40:5B:A5:17:69:87:30:CA:34:68:43:D0:41:AE:F2
StartSSL Class 3 keyid:4E:0B:EF:1A:A4:40:5B:A5:17:69:87:30:CA:34:68:43:D0:41:AE:F2
GeoTrust Global
RapidSSL G3
Comodo
Comodo DV
GlobalSign
GlobalSign DV
================ =================================================================================

In signed certificates
======================

================ =================================================================================
CA               Value
================ =================================================================================
Let's Encrypt    keyid:A8:4A:6A:63:04:7D:DD:BA:E6:D1:39:B7:A6:45:65:EF:F3:A8:EC:A1
StartSSL Class 2 keyid:11:DB:23:45:FD:54:CC:6A:71:6F:84:8A:03:D7:BE:F7:01:2F:26:86
StartSSL Class 3 keyid:B1:3F:1C:92:7B:92:B0:5A:25:B3:38:FB:9C:07:A4:26:50:32:E3:51
RapidSSL G3
Comodo DV
GlobalSign DV
================ =================================================================================

****************
asicConstraints
****************

The ``basicConstraints`` extension specifies if the certificate can be used as a certificate
authority. It is always marked as critical. The ``pathlen`` attribute specifies the levels of
possible intermediate CAs. If not present, the level of intermediate CAs is unlimited, a
``pathlen:0`` means that the CA itself can not issue certificates with ``CA:TRUE`` itself.

In CA certificates
==================

================ =================================================================================
CA               Value
================ =================================================================================
Let's Encrypt    (critical) CA:TRUE, pathlen:0
StartSSL         (critical) CA:TRUE
StartSSL Class 2 (critical) CA:TRUE, pathlen:0
StartSSL Class 3 (critical) CA:TRUE, pathlen:0
GeoTrust Global
RapidSSL G3
Comodo
Comodo DV
GlobalSign
GlobalSign DV
================ =================================================================================

In signed certificates
======================

================ =================================================================================
CA               Value
================ =================================================================================
Let's Encrypt    (critical) CA:FALSE
StartSSL Class 2 (critical) CA:FALSE
StartSSL Class 3 CA:FALSE
RapidSSL G3
Comodo DV
GlobalSign DV
================ =================================================================================

*********************
crlDistributionPoints
*********************

In CA certificates
==================

================ =================================================================================
CA               Value
================ =================================================================================
Let's Encrypt    URI:http://crl.identrust.com/DSTROOTCAX3CRL.crl
StartSSL         URI:http://crl.startssl.com/sfsca.crl
StartSSL Class 2 URI:http://crl.startssl.com/sfsca.crl
StartSSL Class 3 URI:http://crl.startssl.com/sfsca.crl
GeoTrust Global
RapidSSL G3
Comodo
Comodo DV
GlobalSign
GlobalSign DV
================ =================================================================================

In signed certificates
======================

================ =================================================================================
CA               Value
================ =================================================================================
Let's Encrypt    (not present)
StartSSL Class 2 URI:http://crl.startssl.com/crt2-crl.crl
StartSSL Class 3 URI:http://crl.startssl.com/sca-server3.crl
RapidSSL G3
Comodo DV
GlobalSign DV
================ =================================================================================

****************
extendedKeyUsage
****************

In CA certificates
==================

================ =================================================================================
CA               Value
================ =================================================================================
Let's Encrypt    (not present)
StartSSL         (not present)
StartSSL Class 2 (not present)
StartSSL Class 3 TLS Web Client Authentication, TLS Web Server Authentication
GeoTrust Global
RapidSSL G3
Comodo
Comodo DV
GlobalSign
GlobalSign DV
================ =================================================================================

In signed certificates
======================

================ =================================================================================
CA               Value
================ =================================================================================
Let's Encrypt    TLS Web Server Authentication, TLS Web Client Authentication
StartSSL Class 2 TLS Web Client Authentication, TLS Web Server Authentication
StartSSL Class 3 TLS Web Client Authentication, TLS Web Server Authentication
RapidSSL G3
Comodo DV
GlobalSign DV
================ =================================================================================

*************
issuerAltName
*************

In CA certificates
==================

================ =================================================================================
CA               Value
================ =================================================================================
Let's Encrypt    (not present)
StartSSL         (not present)
StartSSL Class 2 (not present)
StartSSL Class 3 (not present)
GeoTrust Global
RapidSSL G3
Comodo
Comodo DV
GlobalSign
GlobalSign DV
================ =================================================================================

In signed certificates
======================

================ =================================================================================
CA               Value
================ =================================================================================
Let's Encrypt
StartSSL Class 2 URI:http://www.startssl.com/
StartSSL Class 3 URI:http://www.startssl.com/
RapidSSL G3
Comodo DV
GlobalSign DV
================ =================================================================================

********
keyUsage
********

In CA certificates
==================

================ =================================================================================
CA               Value
================ =================================================================================
Let's Encrypt    (critical) Digital Signature, Certificate Sign, CRL Sign
StartSSL         (critical) Certificate Sign, CRL Sign
StartSSL Class 2 (critical) Certificate Sign, CRL Sign
StartSSL Class 3 (critical) Certificate Sign, CRL Sign
GeoTrust Global
RapidSSL G3
Comodo
Comodo DV
GlobalSign
GlobalSign DV
================ =================================================================================

In signed certificates
======================

================ =================================================================================
CA               Value
================ =================================================================================
Let's Encrypt    (critical) Digital Signature, Key Encipherment
StartSSL Class 2 Digital Signature, Key Encipherment, Key Agreement
StartSSL Class 3 Digital Signature, Key Encipherment
RapidSSL G3
Comodo DV
GlobalSign DV
================ =================================================================================

********************
subjectKeyIdentifier
********************

In CA certificates
==================

================ =================================================================================
CA               Value
================ =================================================================================
Let's Encrypt    A8:4A:6A:63:04:7D:DD:BA:E6:D1:39:B7:A6:45:65:EF:F3:A8:EC:A1
StartSSL         4E:0B:EF:1A:A4:40:5B:A5:17:69:87:30:CA:34:68:43:D0:41:AE:F2
StartSSL Class 2 11:DB:23:45:FD:54:CC:6A:71:6F:84:8A:03:D7:BE:F7:01:2F:26:86
StartSSL Class 3 B1:3F:1C:92:7B:92:B0:5A:25:B3:38:FB:9C:07:A4:26:50:32:E3:51
GeoTrust Global
RapidSSL G3
Comodo
Comodo DV
GlobalSign
GlobalSign DV
================ =================================================================================

In signed certificates
======================

================ =================================================================================
CA               Value
================ =================================================================================
Let's Encrypt    F4:F3:B8:F5:43:90:2E:A2:7F:DD:51:4A:5F:3E:AC:FB:F1:33:EE:95
StartSSL Class 2 C7:AA:D9:A4:F0:BC:D1:C1:1B:05:D2:19:71:0A:86:F8:58:0F:F0:99
StartSSL Class 3 F0:72:65:5E:21:AA:16:76:2C:6F:D0:63:53:0C:68:D5:89:50:2A:73
RapidSSL G3
Comodo DV
GlobalSign DV
================ =================================================================================

****************
Other extensions
****************

In CA certificates
==================

Extensions used by certificates encountered in the wild that django-ca does not (yet) support in
any way.

================ =================================================================================
CA               Value
================ =================================================================================
Let's Encrypt    X509v3 Certificate Policies, X509v3 Name Constraints
StartSSL         X509v3 Certificate Policies, Netscape Cert Type, Netscape Comment
StartSSL Class 2 X509v3 Certificate Policies
StartSSL Class 3 X509v3 Certificate Policies
GeoTrust Global
RapidSSL G3
Comodo
Comodo DV
GlobalSign
GlobalSign DV
================ =================================================================================


In signed certificates
======================

================ =================================================================================
CA               Value
================ =================================================================================
Let's Encrypt    X509v3 Certificate Policies
StartSSL Class 2 X509v3 Certificate Policies
StartSSL Class 3 X509v3 Certificate Policies
RapidSSL G3
Comodo DV
GlobalSign DV
================ =================================================================================
