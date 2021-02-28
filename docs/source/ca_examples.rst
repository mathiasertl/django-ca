############################
x509 extensions in other CAs
############################

This page documents the x509 extensions (e.g. for CRLs, etc.) set by other CAs. The information
here is used by **django-ca** to initialize and sign certificate authorities and certificates.

Helpful descriptions of the meaning of various extensions can also be found in
:manpage:`x509v3_config(5SSL)` (`online <https://www.openssl.org/docs/manmaster/apps/x509v3_config.html>`_).

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
AuthorityInfoAccess
*******************

.. seealso:: https://tools.ietf.org/html/rfc5280#section-4.2.2.1

The "CA Issuers" is a URI pointing to the signing certificate. The certificate is in DER/ASN1 format
and has a ``Content-Type: application/x-x509-ca-cert`` header (except where noted).

In CA certificates
==================

Let's Encrypt is notable here because its CA Issuers field points to a PKCS#7 file and the HTTP
response returns a ``Content-Type: application/x-pkcs7-mime`` header.

The certificate pointed to by the CA Issuers field is the root certificate (so the Comodo DV CA
points to the AddTrust CA that signed the Comodo Root CA).

.. include:: generated/ca_aia.rst

In signed certificates
======================

Let's Encrypt is again special in that the response has a ``Content-Type: application/pkix-cert``
header (but at least it's in DER format like every other certificate). RapidSSL uses
``Content-Type: text/plain``.

The CA Issuers field sometimes points to the signing certificate (e.g. StartSSL) or to the root CA
(e.g. Comodo DV, which points to the AddTrust Root CA)

.. include:: generated/cert_aia.rst

.. _authorityKeyIdentifier:

**********************
AuthorityKeyIdentifier
**********************

.. seealso:: https://tools.ietf.org/html/rfc5280#section-4.2.1.1

A hash identifying the CA used to sign the certificate. In theory the identifier may also be based
on the issuer name and serial number, but in the wild, all certificates reference the
:ref:`subjectKeyIdentifier`. Self-signed certificates (e.g. Root CAs, like StartSSL and Comodo
below) will reference themself, while signed certificates reference the signed CA, e.g.:

=============== ==================== ======================
Name            SubjectKeyIdentifier AuthorityKeyIdentifier
=============== ==================== ======================
Root CA         foo                  foo
Intermediate CA bar                  foo
Client Cert     foobar               bar
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
BasicConstraints
****************

.. seealso:: https://tools.ietf.org/html/rfc5280#section-4.2.1.9

The BasicConstraints extension specifies if the certificate can be used as a certificate authority. It is
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

.. _ca-example-certificatePolicies:

*******************
CertificatePolicies
*******************

In CA certificates
==================

.. include:: generated/ca_certificatepolicies.rst

In signed certificates
======================

.. include:: generated/cert_certificatepolicies.rst


.. _ca-example-crlDistributionPoints:

*********************
CRLDistributionPoints
*********************

.. seealso:: https://tools.ietf.org/html/rfc5280#section-4.2.1.13

In theory a complex multi-valued extension, this extension usually just holds a URI pointing to a
Certificate Revocation List (CRL).

Root certificate authorities (StartSSL, GeoTrust Global, GlobalSign) do not set this field. This
usually isn't a problem since clients have a list of trusted root certificates anyway, and browsers
and distributions should get regular updates on the list of trusted certificates.

All CRLs linked here are all in DER/ASN1 format, and the ``Content-Type`` header in the response is
set to ``application/pkix-crl``. Only Comodo uses ``application/x-pkcs7-crl``, but it is also in
DER/ASN1 format.

In CA certificates
==================

.. include:: generated/ca_crldp.rst

In signed certificates
======================

Let's Encrypt is so far the only CA that does not maintain a CRL for signed certificates. Major CAs usually
don't fancy CRLs much because they are a large file (e.g. the CRL from Comodo is 1.5MB) containing all
certificates and cause major traffic for CAs. OCSP is just better in every way.

.. include:: generated/cert_crldp.rst

****************
ExtendedKeyUsage
****************

A list of purposes for which the certificate can be used for. CA certificates usually do not set
this field.

In CA certificates
==================

.. include:: generated/ca_eku.rst

In signed certificates
======================

.. include:: generated/cert_eku.rst

*********************
IssuerAlternativeName
*********************

.. seealso:: https://tools.ietf.org/html/rfc5280#section-4.2.1.7

Only StartSSL sets this field in its signed certificates. It's a URI pointing to their homepage.

In CA certificates
==================

.. include:: generated/ca_ian.rst

In signed certificates
======================

.. include:: generated/cert_ian.rst

********
KeyUsage
********

.. seealso:: https://tools.ietf.org/html/rfc5280#section-4.2.1.3

List of permitted key usages. Usually marked as critical, except for certificates signed by
StartSSL.

In CA certificates
==================

.. include:: generated/ca_key_usage.rst

In signed certificates
======================

.. include:: generated/cert_key_usage.rst

.. _nameConstraints:

***************
NameConstraints
***************

.. seealso:: https://tools.ietf.org/html/rfc5280#section-4.2.1.10

This extension is only valid in CAs and must be marked as critical, according to RFC 5280.

Only the expired Let's Encrypt X1 sets this extension to exclude `.mil <https://en.wikipedia.org/wiki/.mil>`_,
and does not set this extension as critical.

In CA certificates
==================

.. include:: generated/ca_nc.rst

In signed certificates
======================

.. include:: generated/cert_nc.rst

.. _precertificatesignedcertificatetimestamps:

*****************************************
PrecertificateSignedCertificateTimestamps
*****************************************

.. seealso:: https://tools.ietf.org/html/rfc6962.html

This extension is used for `Certificate Transparency
<https://en.wikipedia.org/wiki/Certificate_Transparency>`_ and only makes sense in client certificates. It is
usually not marked as critical (since many clients do not support Certificate Transparency).

In CA certificates
==================

.. include:: generated/ca_sct.rst

In signed certificates
======================

.. include:: generated/cert_sct.rst

.. _subjectAltName:

**********************
SubjectAlternativeName
**********************

The SubjectAlternativeName extension is not present in any CA certificate, and of course whatever the customer
requests in signed certificates.

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
SubjectKeyIdentifier
********************

.. seealso:: https://tools.ietf.org/html/rfc5280#section-4.2.1.2

The SubjectKeyIdentifier extension provides a means of identifying certificates. It is a
mandatory extension for CA certificates. Currently only RapidSSL does not set this for signed
certificates.

The value of the SubjectKeyIdentifier extension reappears in the :ref:`authorityKeyIdentifier`
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

Currently only the old StartSSL root CA has any unknown extension.

.. include:: generated/ca_unknown.rst

In signed certificates
======================

Currently no tested cert has any unknown extensions.

.. include:: generated/cert_unknown.rst

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

AuthorityKeyIdentifier
======================

The value of this extension matches the SubjectKeyIdentifier of the CA that signed the CRL.

.. seealso:: https://tools.ietf.org/html/rfc5280.html#section-5.2.1


.. include:: generated/crl_aki.rst

cRLNumber
=========

.. include:: generated/crl_crlnumber.rst

IssuingDistributionPoint
========================

.. include:: generated/crl_idp.rst
