############################
x509 extensions in other CAs
############################

This page documents the x509 extensions (e.g. for CRLs, etc.) set by other CAs. The information
here is used by **django-ca** to initialize and sign certificate authorities and certificates.

Helpful descriptions of the meaning of various extensions can also be found in
:manpage:`x509v3_config(5SSL)` (`online
<https://www.openssl.org/docs/manmaster/apps/x509v3_config.html>`_).

*******
Subject
*******

In CA certificates
==================

.. include:: generated/ca_subject.rst

In signed certificates
======================

.. include:: generated/cert_subject.rst

******
Issuer
******

The issuer is an X509 Name naming who signed the certificate. For root CAs, the
issuer has the same value as the subject.

In CA certificates
==================

.. include:: generated/ca_issuer.rst

In signed certificates
======================

.. include:: generated/cert_issuer.rst


*******************
authorityInfoAccess
*******************

.. seealso:: https://tools.ietf.org/html/rfc5280#section-4.2.2.1

The "CA Issuers" is a URI pointing to the signing certificate. The certificate is in DER/ASN1 format
and has a ``Content-Type: application/x-x509-ca-cert`` header (except where noted).

In CA certificates
==================

Let's Encrypt is notable here because its CA Issuers field points to a pkcs7 file and the HTTP
response returns a ``Content-Type: application/x-pkcs7-mime`` header.

The certificate pointed to by the CA Issuers field is the root certificate (so the Comodo DV CA
points to the AddTrust CA that signed the Comodo Root CA).

================= =================================================================================
CA                Value
================= =================================================================================
Let's Encrypt X1  * OCSP - URI:http://isrg.trustid.ocsp.identrust.com
                  * CA Issuers - URI:http://apps.identrust.com/roots/dstrootcax3.p7c
Let's Encrypt X3  * OCSP - URI:http://isrg.trustid.ocsp.identrust.com
                  * CA Issuers - URI:http://apps.identrust.com/roots/dstrootcax3.p7c
StartSSL          (not present)
StartSSL Class 2  * OCSP - URI:http://ocsp.startssl.com/ca
                  * CA Issuers - URI:http://aia.startssl.com/certs/ca.crt
StartSSL Class 3  * OCSP - URI:http://ocsp.startssl.com
                  * CA Issuers - URI:http://aia.startssl.com/certs/ca.crt
GeoTrust Global   (not present)
RapidSSL G3       OCSP - URI:http://g.symcd.com
Comodo            OCSP - URI:http://ocsp.usertrust.com
Comodo DV         * CA Issuers - URI:http://crt.comodoca.com/COMODORSAAddTrustCA.crt
                  * OCSP - URI:http://ocsp.comodoca.com
GlobalSign        (not present)
GlobalSign DV     OCSP - URI:http://ocsp.globalsign.com/rootr1
================= =================================================================================


In signed certificates
======================

Let's Encrypt is again special in that the response has a ``Content-Type: application/pkix-cert``
header (but at least it's in DER format like every other certificate). RapidSSL uses
``Content-Type: text/plain``.

The CA Issuers field sometimes points to the signing certificate (e.g. StartSSL) or to the root CA
(e.g. Comodo DV, which points to the AddTrust Root CA)

================ =================================================================================
CA               Value
================ =================================================================================
Let's Encrypt X1 * OCSP - URI:http://ocsp.int-x1.letsencrypt.org/
                 * CA Issuers - URI:http://cert.int-x1.letsencrypt.org
Let's Encrypt X3 * OCSP - URI:http://ocsp.int-x3.letsencrypt.org/
                 * CA Issuers - URI:http://cert.int-x3.letsencrypt.org/
StartSSL Class 2 * OCSP - URI:http://ocsp.startssl.com/sub/class2/server/ca
                 * CA Issuers - URI:http://aia.startssl.com/certs/sub.class2.server.ca.crt
StartSSL Class 3 * OCSP - URI:http://ocsp.startssl.com
                 * CA Issuers - URI:http://aia.startssl.com/certs/sca.server3.crt
RapidSSL G3      * OCSP - URI:http://gv.symcd.com
                 * CA Issuers - URI:http://gv.symcb.com/gv.crt
Comodo DV        * CA Issuers - URI:http://crt.comodoca.com/COMODORSADomainValidationSecureServerCA.crt
                 * OCSP - URI:http://ocsp.comodoca.com
GlobalSign DV    * CA Issuers - URI:http://secure.globalsign.com/cacert/gsdomainvalsha2g2r1.crt
                 * OCSP - URI:http://ocsp2.globalsign.com/gsdomainvalsha2g2
================ =================================================================================

.. _authorityKeyIdentifier:

**********************
authorityKeyIdentifier
**********************

.. seealso:: https://tools.ietf.org/html/rfc5280#section-4.2.1.1

A hash identifying the CA used to sign the certificate. In theory the identifier may also be based
on the issuer name and serial number, but in the wild, all certificates reference the
:ref:`subjectKeyIdentifier`. Self-signed certificates (e.g. Root CAs, like StartSSL and Comodo
below) will reference themself, while signed certificates reference the signed CA, e.g.:

=============== ==================== ======================
Name            subjectKeyIdentifier authorityKeyIdentifier
=============== ==================== ======================
Root CA         foo                  foo
Intermediate CA bar                  foo
Client Cert     bla                  bar
=============== ==================== ======================

In CA certificates
==================

Root CAs usually have a value identical to the :ref:`subjectKeyIdentifier`, but
some root CAs do not include this extension at all.

.. include:: generated/ca_aki.rst

In signed certificates
======================

.. include:: generated/cert_aki.rst

****************
basicConstraints
****************

.. seealso:: https://tools.ietf.org/html/rfc5280#section-4.2.1.9

The ``basicConstraints`` extension specifies if the certificate can be used as a certificate authority. It is
always marked as critical. The ``pathlen`` attribute specifies the levels of possible intermediate CAs. If not
present, the level of intermediate CAs is unlimited, a ``pathlen:0`` means that the CA itself can not issue
certificates with ``CA:TRUE`` itself.

In CA certificates
==================

Most root CAs do not set a Path Length, while most (but not all) intermediate CAs set a Path Length of 0.

.. include:: generated/ca_basicconstraints.rst

In signed certificates
======================

Notable here that some end-user certificates do not mark this extension as critical.

.. include:: generated/cert_basicconstraints.rst

.. _ca-example-crlDistributionPoints:

*********************
crlDistributionPoints
*********************

.. seealso:: https://tools.ietf.org/html/rfc5280#section-4.2.1.13

In theory a complex multi-valued extension, this extension usually just holds a URI pointing to a
Certificate Revokation List (CRL).

Root certificate authorities (StartSSL, GeoTrust Global, GlobalSign) do not set this field. This
usually isn't a problem since clients have a list of trusted root certificates anyway, and browsers
and distributions should get regular updates on the list of trusted certificates.

All CRLs linked here are all in DER/ASN1 format, and the ``Content-Type`` header in the response is
set to ``application/pkix-crl``. Only Comodo uses ``application/x-pkcs7-crl``, but it is also in
DER/ASN1 format.

In CA certificates
==================

================ =============================================================== =======================
CA               Value                                                           Content-Type
================ =============================================================== =======================
Let's Encrypt X1 URI:http://crl.identrust.com/DSTROOTCAX3CRL.crl                 application/pkix-crl
Let's Encrypt X3 URI:http://crl.identrust.com/DSTROOTCAX3CRL.crl                 application/pkix-crl  
StartSSL         (not present)
StartSSL Class 2 URI:http://crl.startssl.com/sfsca.crl                           application/pkix-crl
StartSSL Class 3 URI:http://crl.startssl.com/sfsca.crl                           application/pkix-crl
GeoTrust Global  (not present)
RapidSSL G3      URI:http://g.symcb.com/crls/gtglobal.crl                        application/pkix-crl
Comodo           URI:http://crl.usertrust.com/AddTrustExternalCARoot.crl         application/x-pkcs7-crl
Comodo DV        URI:http://crl.comodoca.com/COMODORSACertificationAuthority.crl application/x-pkcs7-crl
GlobalSign       (not present)
GlobalSign DV    URI:http://crl.globalsign.net/root.crl                          application/pkix-crl
================ =============================================================== =======================

In signed certificates
======================

Let's Encrypt is so far the only CA that does not maintain a CRL for signed certificates. Major CAs
usually don't fancy CRLs much because they are a large file (e.g. Comodos CRL is 1.5MB) containing
all certificates and cause major traffic for CAs. OCSP is just better in every way.

================ ======================================================================== =======================
CA               Value                                                                    Content-Type
================ ======================================================================== =======================
Let's Encrypt    (not present)
StartSSL Class 2 URI:http://crl.startssl.com/crt2-crl.crl                                 application/pkix-crl
StartSSL Class 3 URI:http://crl.startssl.com/sca-server3.crl                              application/pkix-crl
RapidSSL G3      URI:http://gv.symcb.com/gv.crl                                           application/pkix-crl
Comodo DV        URI:http://crl.comodoca.com/COMODORSADomainValidationSecureServerCA.crl  application/x-pkcs7-crl
GlobalSign DV    URI:http://crl.globalsign.com/gs/gsdomainvalsha2g2.crl                   application/pkix-crl
================ ======================================================================== =======================

****************
extendedKeyUsage
****************

A list of purposes for which the certificate can be used for. CA certificates usually do not set
this field.

In CA certificates
==================

================ =================================================================================
CA               Value
================ =================================================================================
Let's Encrypt X1 (not present)
Let's Encrypt X3 (not present)
StartSSL         (not present)
StartSSL Class 2 (not present)
StartSSL Class 3 TLS Web Client Authentication, TLS Web Server Authentication
GeoTrust Global  (not present)
RapidSSL G3      (not present)
Comodo           (not present)
Comodo DV        TLS Web Server Authentication, TLS Web Client Authentication
GlobalSign       (not present)
GlobalSign DV    (not present)
================ =================================================================================

In signed certificates
======================

================ =================================================================================
CA               Value
================ =================================================================================
Let's Encrypt X1 TLS Web Server Authentication, TLS Web Client Authentication
Let's Encrypt X3 TLS Web Server Authentication, TLS Web Client Authentication  
StartSSL Class 2 TLS Web Client Authentication, TLS Web Server Authentication
StartSSL Class 3 TLS Web Client Authentication, TLS Web Server Authentication
RapidSSL G3      TLS Web Server Authentication, TLS Web Client Authentication
Comodo DV        TLS Web Server Authentication, TLS Web Client Authentication
GlobalSign DV    TLS Web Server Authentication, TLS Web Client Authentication
================ =================================================================================

*************
issuerAltName
*************

.. seealso:: https://tools.ietf.org/html/rfc5280#section-4.2.1.7

Only StartSSL sets this field in its signed certificates. It's a URI pointing to their homepage.

In CA certificates
==================

================ =================================================================================
CA               Value
================ =================================================================================
Let's Encrypt    (not present)
StartSSL         (not present)
StartSSL Class 2 (not present)
StartSSL Class 3 (not present)
GeoTrust Global  (not present)
RapidSSL G3      (not present)
Comodo           (not present)
Comodo DV        (not present)
GlobalSign       (not present)
GlobalSign DV    (not present)
================ =================================================================================

In signed certificates
======================

================ =================================================================================
CA               Value
================ =================================================================================
Let's Encrypt    (not present)
StartSSL Class 2 URI:http://www.startssl.com/
StartSSL Class 3 URI:http://www.startssl.com/
RapidSSL G3      (not present)
Comodo DV        (not present)
GlobalSign DV    (not present)
================ =================================================================================

********
keyUsage
********

.. seealso:: https://tools.ietf.org/html/rfc5280#section-4.2.1.3

List of permitted key usages. Usually marked as critical, except for certificates signed by
StartSSL.

In CA certificates
==================

================ =================================================================================
CA               Value
================ =================================================================================
Let's Encrypt X1 (critical) Digital Signature, Certificate Sign, CRL Sign
Let's Encrypt X3 (critical) Digital Signature, Certificate Sign, CRL Sign 
StartSSL         (critical) Certificate Sign, CRL Sign
StartSSL Class 2 (critical) Certificate Sign, CRL Sign
StartSSL Class 3 (critical) Certificate Sign, CRL Sign
GeoTrust Global  (critical) Certificate Sign, CRL Sign
RapidSSL G3      (critical) Certificate Sign, CRL Sign
Comodo           (critical) Digital Signature, Certificate Sign, CRL Sign
Comodo DV        (critical) Digital Signature, Certificate Sign, CRL Sign
GlobalSign       (critical) Certificate Sign, CRL Sign
GlobalSign DV    (critical) Certificate Sign, CRL Sign
================ =================================================================================

In signed certificates
======================

================ =================================================================================
CA               Value
================ =================================================================================
Let's Encrypt X1 (critical) Digital Signature, Key Encipherment
Let's Encrypt X3 (critical) Digital Signature, Key Encipherment 
StartSSL Class 2 Digital Signature, Key Encipherment, Key Agreement
StartSSL Class 3 Digital Signature, Key Encipherment
RapidSSL G3      (critical) Digital Signature, Key Encipherment
Comodo DV        (critical) Digital Signature, Key Encipherment
GlobalSign DV    (critical) Digital Signature, Key Encipherment
================ =================================================================================

.. _subjectAltName:

**************
subjectAltName
**************

The ``subjectAltName`` extension is not present in any CA certificate, and of course whatever the
customer requests in signed certificates.

In CA certificates
==================

================ =================================================================================
CA               Value
================ =================================================================================
Let's Encrypt    -
StartSSL         -
StartSSL Class 2 -
StartSSL Class 3 -
GeoTrust Global  -
RapidSSL G3      -
Comodo           -
Comodo DV        -
GlobalSign       -
GlobalSign DV    -
================ =================================================================================

.. _subjectKeyIdentifier:

********************
subjectKeyIdentifier
********************

.. seealso:: https://tools.ietf.org/html/rfc5280#section-4.2.1.2

The subjectKeyIdentifier extension provides a means of identifying certificates. It is a
mandatory extension for CA certificates. Currently only RapidSSL does not set this for signed
certificates.

The value of the subjectKeyIdentifier extension reappears in the :ref:`authorityKeyIdentifier`
extension.

In CA certificates
==================

.. include:: generated/ca_ski.rst

In signed certificates
======================

.. include:: generated/cert_ski.rst

****************
Other extensions
****************

Extensions used by certificates encountered in the wild that django-ca does not (yet) support in
any way.

In CA certificates
==================

================ =================================================================================
CA               Value
================ =================================================================================
Let's Encrypt X1 X509v3 Certificate Policies, X509v3 Name Constraints
Let's Encrypt X3 X509v3 Certificate Policies  
StartSSL         X509v3 Certificate Policies, Netscape Cert Type, Netscape Comment
StartSSL Class 2 X509v3 Certificate Policies
StartSSL Class 3 X509v3 Certificate Policies
GeoTrust Global  (none)
RapidSSL G3      X509v3 Certificate Policies
Comodo           X509v3 Certificate Policies
Comodo DV        X509v3 Certificate Policies
GlobalSign       (none)
GlobalSign DV    X509v3 Certificate Policies
================ =================================================================================


In signed certificates
======================

================ =================================================================================
CA               Value
================ =================================================================================
Let's Encrypt X1 X509v3 Certificate Policies
Let's Encrypt X3 X509v3 Certificate Policies
StartSSL Class 2 X509v3 Certificate Policies
StartSSL Class 3 X509v3 Certificate Policies
RapidSSL G3      X509v3 Certificate Policies
Comodo DV        X509v3 Certificate Policies
GlobalSign DV    X509v3 Certificate Policies
================ =================================================================================


**************
CRL Extensions
**************

The values of extensions and values of CRLs found in the wild.

.. include:: generated/crl_info.rst

Data
====

.. include:: generated/crl_data.rst

Issuer
======

.. include:: generated/crl_issuer.rst

authorityKeyIdentifier
======================

.. include:: generated/crl_aki.rst

cRLNumber
=========

.. include:: generated/crl_crlnumber.rst

issuingDistributionPoint
========================

.. include:: generated/crl_idp.rst
