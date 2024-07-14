# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca. If not, see
# <http://www.gnu.org/licenses/>.

"""Collection of constants used by django-ca."""

import enum
from collections import defaultdict
from types import MappingProxyType

import asn1crypto.core
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificateIssuerPublicKeyTypes,
)
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.certificate_transparency import LogEntryType
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID as _ExtendedKeyUsageOID,
    ExtensionOID,
    NameOID,
    SubjectInformationAccessOID,
)

from django.utils.translation import gettext_lazy as _

# IMPORTANT: Do **not** import any module from django_ca at runtime here, or you risk circular imports.
from django_ca.typehints import (
    AccessMethods,
    AllowedHashTypes,
    CertificateExtensionKeys,
    CertificateRevocationListEncodingNames,
    CertificateRevocationListEncodings,
    ConfigurableExtensionKeys,
    EllipticCurves,
    EndEntityCertificateExtensionKeys,
    ExtensionKeys,
    GeneralNames,
    HashAlgorithms,
    KeyUsages,
    OtherNames,
    ParsableKeyType,
)

ACCESS_METHOD_TYPES: MappingProxyType[AccessMethods, x509.ObjectIdentifier] = MappingProxyType(
    {
        "ocsp": AuthorityInformationAccessOID.OCSP,
        "ca_issuers": AuthorityInformationAccessOID.CA_ISSUERS,
        "ca_repository": SubjectInformationAccessOID.CA_REPOSITORY,
    }
)

#: Types of encodings available for certificate revocation lists (CRLs).
CERTIFICATE_REVOCATION_LIST_ENCODING_TYPES: MappingProxyType[
    CertificateRevocationListEncodingNames, CertificateRevocationListEncodings
] = MappingProxyType({"PEM": Encoding.PEM, "DER": Encoding.DER})
CERTIFICATE_REVOCATION_LIST_ENCODING_NAMES: MappingProxyType[
    CertificateRevocationListEncodings, CertificateRevocationListEncodingNames
] = MappingProxyType({v: k for k, v in CERTIFICATE_REVOCATION_LIST_ENCODING_TYPES.items()})

DEFAULT_STORAGE_BACKEND = "django_ca.key_backends.storages.StoragesBackend"

#: Mapping of elliptic curve names to the implementing classes
ELLIPTIC_CURVE_TYPES: MappingProxyType[EllipticCurves, type[ec.EllipticCurve]] = MappingProxyType(
    {
        "sect571r1": ec.SECT571R1,
        "sect409r1": ec.SECT409R1,
        "sect283r1": ec.SECT283R1,
        "sect233r1": ec.SECT233R1,
        "sect163r2": ec.SECT163R2,
        "sect571k1": ec.SECT571K1,
        "sect409k1": ec.SECT409K1,
        "sect283k1": ec.SECT283K1,
        "sect233k1": ec.SECT233K1,
        "sect163k1": ec.SECT163K1,
        "secp521r1": ec.SECP521R1,
        "secp384r1": ec.SECP384R1,
        "secp256r1": ec.SECP256R1,
        "secp256k1": ec.SECP256K1,
        "secp224r1": ec.SECP224R1,
        "secp192r1": ec.SECP192R1,
        "brainpoolP256r1": ec.BrainpoolP256R1,
        "brainpoolP384r1": ec.BrainpoolP384R1,
        "brainpoolP512r1": ec.BrainpoolP512R1,
    }
)

ELLIPTIC_CURVE_NAMES: MappingProxyType[type[ec.EllipticCurve], EllipticCurves] = MappingProxyType(
    {v: k for k, v in ELLIPTIC_CURVE_TYPES.items()}
)


class ExtendedKeyUsageOID(_ExtendedKeyUsageOID):
    """Extend the OIDs known to cryptography with what users needed over the years."""

    # Defined in RFC 3280, occurs in TrustID Server A52 CA
    IPSEC_END_SYSTEM = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.5")
    IPSEC_TUNNEL = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.6")
    IPSEC_USER = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.7")

    # mobile Driving Licence or mDL (see ISO/IEC DIS 18013-5, GitHub PR #81)
    MDL_DOCUMENT_SIGNER = x509.ObjectIdentifier("1.0.18013.5.1.2")
    MDL_JWS_CERTIFICATE = x509.ObjectIdentifier("1.0.18013.5.1.3")


#: Map of ExtendedKeyUsageOIDs to names in RFC 5280 (and other RFCs).
EXTENDED_KEY_USAGE_NAMES = MappingProxyType(
    {
        ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE: "anyExtendedKeyUsage",
        ExtendedKeyUsageOID.CERTIFICATE_TRANSPARENCY: "certificateTransparency",
        ExtendedKeyUsageOID.CLIENT_AUTH: "clientAuth",
        ExtendedKeyUsageOID.CODE_SIGNING: "codeSigning",
        ExtendedKeyUsageOID.EMAIL_PROTECTION: "emailProtection",
        ExtendedKeyUsageOID.IPSEC_END_SYSTEM: "ipsecEndSystem",
        ExtendedKeyUsageOID.IPSEC_IKE: "ipsecIKE",
        ExtendedKeyUsageOID.IPSEC_TUNNEL: "ipsecTunnel",
        ExtendedKeyUsageOID.IPSEC_USER: "ipsecUser",
        ExtendedKeyUsageOID.KERBEROS_PKINIT_KDC: "msKDC",
        ExtendedKeyUsageOID.MDL_DOCUMENT_SIGNER: "mdlDS",
        ExtendedKeyUsageOID.MDL_JWS_CERTIFICATE: "mdlJWS",
        ExtendedKeyUsageOID.OCSP_SIGNING: "OCSPSigning",
        ExtendedKeyUsageOID.SERVER_AUTH: "serverAuth",
        ExtendedKeyUsageOID.SMARTCARD_LOGON: "smartcardLogon",
        ExtendedKeyUsageOID.TIME_STAMPING: "timeStamping",
    }
)

#: Map of Extended Key Usage names to ExtendedKeyUsageOID (the inverse of EXTENDED_KEY_USAGE_NAMES).
EXTENDED_KEY_USAGE_OIDS = MappingProxyType({v: k for k, v in EXTENDED_KEY_USAGE_NAMES.items()})

#: Map of ExtendedKeyUsageOIDs to human-readable names.
EXTENDED_KEY_USAGE_HUMAN_READABLE_NAMES = MappingProxyType(
    {
        ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE: "Any Extended Key Usage",
        ExtendedKeyUsageOID.CERTIFICATE_TRANSPARENCY: "Certificate Transparency",
        ExtendedKeyUsageOID.CLIENT_AUTH: "SSL/TLS Web Client Authentication",
        ExtendedKeyUsageOID.CODE_SIGNING: "Code signing",
        ExtendedKeyUsageOID.EMAIL_PROTECTION: "E-mail Protection (S/MIME)",
        ExtendedKeyUsageOID.IPSEC_END_SYSTEM: "IPSec EndSystem",
        ExtendedKeyUsageOID.IPSEC_IKE: "IPSec Internet Key Exchange",
        ExtendedKeyUsageOID.IPSEC_TUNNEL: "IPSec Tunnel",
        ExtendedKeyUsageOID.IPSEC_USER: "IPSec User",
        ExtendedKeyUsageOID.KERBEROS_PKINIT_KDC: "Kerberos Domain Controller",
        ExtendedKeyUsageOID.MDL_DOCUMENT_SIGNER: "mdlDS",
        ExtendedKeyUsageOID.MDL_JWS_CERTIFICATE: "mdlJWS",
        ExtendedKeyUsageOID.OCSP_SIGNING: "OCSP Signing",
        ExtendedKeyUsageOID.SERVER_AUTH: "SSL/TLS Web Server Authentication",
        ExtendedKeyUsageOID.SMARTCARD_LOGON: "Smart card logon",
        ExtendedKeyUsageOID.TIME_STAMPING: "Trusted Timestamping",
    }
)

EXTENSION_DESCRIPTIONS = MappingProxyType(
    {
        ExtensionOID.ISSUER_ALTERNATIVE_NAME: _(
            "This extension is used to associate alternative names with the certificate issuer. Rarely used "
            "in practice."
        )
    }
)

#: Map of ExtensionOIDs to a human-readable text describing if the extension should/must/... be critical.
EXTENSION_CRITICAL_HELP = MappingProxyType(
    {
        ExtensionOID.AUTHORITY_INFORMATION_ACCESS: _("MUST be non-critical"),
        ExtensionOID.AUTHORITY_KEY_IDENTIFIER: _("MUST be non-critical"),
        ExtensionOID.BASIC_CONSTRAINTS: _("MUST usually be critical, but allows non-critical in some cases"),
        ExtensionOID.CERTIFICATE_POLICIES: _("may or may not be critical (recommended: non-critical)"),
        ExtensionOID.CRL_DISTRIBUTION_POINTS: _("SHOULD be non-critical"),
        ExtensionOID.CRL_NUMBER: _("is non-critical"),
        ExtensionOID.DELTA_CRL_INDICATOR: _("is critical"),
        ExtensionOID.EXTENDED_KEY_USAGE: _("MAY, at your discretion, be either critical or non-critical"),
        ExtensionOID.FRESHEST_CRL: _("MUST be non-critical"),
        ExtensionOID.INHIBIT_ANY_POLICY: _("MUST be critical"),
        ExtensionOID.ISSUER_ALTERNATIVE_NAME: _("SHOULD be non-critical"),
        ExtensionOID.ISSUING_DISTRIBUTION_POINT: _("is critical"),
        ExtensionOID.KEY_USAGE: _("SHOULD be critical"),
        ExtensionOID.MS_CERTIFICATE_TEMPLATE: _("may or may not be critical."),
        ExtensionOID.NAME_CONSTRAINTS: _("MUST be critical"),
        ExtensionOID.OCSP_NO_CHECK: _("SHOULD be a non-critical"),  # defined in RFC 2560
        ExtensionOID.POLICY_CONSTRAINTS: _("MUST be critical"),
        ExtensionOID.POLICY_MAPPINGS: _("SHOULD  be critical"),
        ExtensionOID.PRECERT_POISON: _("MUST be critical"),  # defined in RFC 6962
        ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS: _(  # defined in RFC 6962
            "may or may not be critical (recommended: non-critical)"
        ),
        ExtensionOID.SIGNED_CERTIFICATE_TIMESTAMPS: _(  # defined in RFC 6962
            "may or may not be critical (recommended: non-critical)"
        ),
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME: _("SHOULD be non-critical"),
        ExtensionOID.SUBJECT_INFORMATION_ACCESS: _("MUST be non-critical"),
        ExtensionOID.SUBJECT_KEY_IDENTIFIER: _("MUST be non-critical"),
        ExtensionOID.TLS_FEATURE: _("SHOULD NOT be critical"),  # defined in RFC 7633
        ExtensionOID.SUBJECT_DIRECTORY_ATTRIBUTES: _("MUST be non-critical"),
    }
)

#: Map of ExtensionOIDs to the default critical values as defined in the RFC where they are defined.
EXTENSION_DEFAULT_CRITICAL = MappingProxyType(
    {
        ExtensionOID.AUTHORITY_INFORMATION_ACCESS: False,  # MUST mark this extension as non-critical.
        ExtensionOID.AUTHORITY_KEY_IDENTIFIER: False,  # MUST mark this extension as non-critical
        ExtensionOID.BASIC_CONSTRAINTS: True,  # RFC 5280 is more complex here, True is a good efault
        ExtensionOID.CERTIFICATE_POLICIES: False,  # RFC 5280 does not say (!)
        ExtensionOID.CRL_DISTRIBUTION_POINTS: False,  # The extension SHOULD be non-critical
        ExtensionOID.CRL_NUMBER: False,  # is a non-critical CRL extension
        ExtensionOID.DELTA_CRL_INDICATOR: True,  # is a critical CRL extension
        ExtensionOID.EXTENDED_KEY_USAGE: False,  # at issuers discretion, but non-critical in the real world.
        ExtensionOID.FRESHEST_CRL: False,  # MUST be marked as non-critical
        ExtensionOID.INHIBIT_ANY_POLICY: True,  # MUST mark this extension as critical
        ExtensionOID.ISSUER_ALTERNATIVE_NAME: False,  # SHOULD mark this extension as non-critical.
        ExtensionOID.ISSUING_DISTRIBUTION_POINT: True,  # is a critical CRL extension
        ExtensionOID.KEY_USAGE: True,  # SHOULD mark this extension as critical.
        ExtensionOID.NAME_CONSTRAINTS: True,  # MUST mark this extension as critical
        ExtensionOID.OCSP_NO_CHECK: False,  # RFC 2560: SHOULD be a non-critical
        ExtensionOID.POLICY_CONSTRAINTS: True,  # MUST mark this extension as critical
        ExtensionOID.POLICY_MAPPINGS: True,  # SHOULD mark this extension as critical
        ExtensionOID.PRECERT_POISON: True,  # RFC 6962: "critical poison extension"
        ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS: False,  # RFC 6962 doesn't say
        ExtensionOID.SIGNED_CERTIFICATE_TIMESTAMPS: False,  # RFC 6962 doesn't say
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME: False,  # SHOULD mark the extension as non-critical.
        ExtensionOID.SUBJECT_DIRECTORY_ATTRIBUTES: False,  # MUST mark this extension as non-critical
        ExtensionOID.SUBJECT_INFORMATION_ACCESS: False,  # MUST mark this extension as non-critical
        ExtensionOID.SUBJECT_KEY_IDENTIFIER: False,  # MUST mark this extension as non-critical
        ExtensionOID.TLS_FEATURE: False,  # RFC 7633: SHOULD NOT be marked critical
    }
)

CONFIGURABLE_EXTENSION_KEYS: MappingProxyType[x509.ObjectIdentifier, ConfigurableExtensionKeys] = (
    MappingProxyType(
        {
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS: "authority_information_access",
            ExtensionOID.CERTIFICATE_POLICIES: "certificate_policies",
            ExtensionOID.CRL_DISTRIBUTION_POINTS: "crl_distribution_points",
            ExtensionOID.EXTENDED_KEY_USAGE: "extended_key_usage",
            ExtensionOID.FRESHEST_CRL: "freshest_crl",
            ExtensionOID.ISSUER_ALTERNATIVE_NAME: "issuer_alternative_name",
            ExtensionOID.KEY_USAGE: "key_usage",
            ExtensionOID.MS_CERTIFICATE_TEMPLATE: "ms_certificate_template",
            ExtensionOID.OCSP_NO_CHECK: "ocsp_no_check",  # RFC 2560 does not really define a spelling
            ExtensionOID.PRECERT_POISON: "precert_poison",  # RFC 7633
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME: "subject_alternative_name",
            ExtensionOID.TLS_FEATURE: "tls_feature",  # RFC 7633
        }
    )
)
CONFIGURABLE_EXTENSION_KEY_OIDS = MappingProxyType({v: k for k, v in CONFIGURABLE_EXTENSION_KEYS.items()})

#: Map of :py:class:`~cryptography.x509.oid.ExtensionOID` to keys that may exist in an end entity certificate.
END_ENTITY_CERTIFICATE_EXTENSION_KEYS: MappingProxyType[
    x509.ObjectIdentifier, EndEntityCertificateExtensionKeys
] = MappingProxyType(
    {
        **CONFIGURABLE_EXTENSION_KEYS,
        ExtensionOID.AUTHORITY_KEY_IDENTIFIER: "authority_key_identifier",
        ExtensionOID.BASIC_CONSTRAINTS: "basic_constraints",
        ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS: "precertificate_signed_certificate_timestamps",  # RFC 7633  # NOQA: E501
        ExtensionOID.SIGNED_CERTIFICATE_TIMESTAMPS: "signed_certificate_timestamps",  # RFC 7633
        ExtensionOID.SUBJECT_INFORMATION_ACCESS: "subject_information_access",
        ExtensionOID.SUBJECT_KEY_IDENTIFIER: "subject_key_identifier",
    }
)

#: Map of extension keys to ExtensionOIDs (the inverse of END_ENTITY_CERTIFICATE_EXTENSION_KEYS).
END_ENTITY_CERTIFICATE_EXTENSION_KEY_OIDS: MappingProxyType[
    EndEntityCertificateExtensionKeys, x509.ObjectIdentifier
] = MappingProxyType({v: k for k, v in END_ENTITY_CERTIFICATE_EXTENSION_KEYS.items()})

#: Map of :py:class:`~cryptography.x509.oid.ExtensionOID` to keys that may exist in any certificate.
#:
#: This value is based on :py:attr:`~django_ca.constants.END_ENTITY_CERTIFICATE_EXTENSION_KEYS` and adds
#: extensions that occur only in certificate authorities.
CERTIFICATE_EXTENSION_KEYS: MappingProxyType[x509.ObjectIdentifier, CertificateExtensionKeys] = (
    MappingProxyType(
        {
            **END_ENTITY_CERTIFICATE_EXTENSION_KEYS,
            ExtensionOID.INHIBIT_ANY_POLICY: "inhibit_any_policy",  # CA only
            ExtensionOID.NAME_CONSTRAINTS: "name_constraints",  # CA only
            ExtensionOID.POLICY_CONSTRAINTS: "policy_constraints",  # CA only
        }
    )
)
CERTIFICATE_EXTENSION_KEY_OIDS = MappingProxyType({v: k for k, v in CERTIFICATE_EXTENSION_KEYS.items()})

#: Map of all :py:class:`~cryptography.x509.oid.ExtensionOID` to keys that are known to cryptography.
#:
#: This value is based on :py:attr:`~django_ca.constants.CERTIFICATE_EXTENSION_KEYS` and adds extensions for
#: CRLs and object identifiers where no corresponding cryptography class exists.
EXTENSION_KEYS: MappingProxyType[x509.ObjectIdentifier, ExtensionKeys] = MappingProxyType(
    {
        **CERTIFICATE_EXTENSION_KEYS,
        ExtensionOID.CRL_NUMBER: "crl_number",  # CRL extension
        ExtensionOID.DELTA_CRL_INDICATOR: "delta_crl_indicator",  # CRL extension
        ExtensionOID.ISSUING_DISTRIBUTION_POINT: "issuing_distribution_point",  # CRL extension
        ExtensionOID.POLICY_MAPPINGS: "policy_mappings",  # only OID exists
        ExtensionOID.SUBJECT_DIRECTORY_ATTRIBUTES: "subject_directory_attributes",  # only OID exists
    }
)

#: Map of extension keys to ExtensionOIDs (the inverse of EXTENSION_KEYS).
EXTENSION_KEY_OIDS: MappingProxyType[ExtensionKeys, x509.ObjectIdentifier] = MappingProxyType(
    {v: k for k, v in EXTENSION_KEYS.items()}
)

#: Map of ExtensionOIDs to human-readable names as they appear in the RFC where they are defined.
EXTENSION_NAMES = MappingProxyType(
    {
        ExtensionOID.AUTHORITY_INFORMATION_ACCESS: "Authority Information Access",
        ExtensionOID.AUTHORITY_KEY_IDENTIFIER: "Authority Key Identifier",
        ExtensionOID.BASIC_CONSTRAINTS: "Basic Constraints",
        ExtensionOID.CERTIFICATE_POLICIES: "Certificate Policies",
        ExtensionOID.CRL_DISTRIBUTION_POINTS: "CRL Distribution Points",
        ExtensionOID.CRL_NUMBER: "CRL Number",
        ExtensionOID.DELTA_CRL_INDICATOR: "Delta CRL Indicator",
        ExtensionOID.EXTENDED_KEY_USAGE: "Extended Key Usage",
        ExtensionOID.FRESHEST_CRL: "Freshest CRL",
        ExtensionOID.INHIBIT_ANY_POLICY: "Inhibit anyPolicy",
        ExtensionOID.ISSUER_ALTERNATIVE_NAME: "Issuer Alternative Name",
        ExtensionOID.ISSUING_DISTRIBUTION_POINT: "Issuing Distribution Point",
        ExtensionOID.KEY_USAGE: "Key Usage",
        ExtensionOID.MS_CERTIFICATE_TEMPLATE: "MS Certificate Template",
        ExtensionOID.NAME_CONSTRAINTS: "Name Constraints",
        ExtensionOID.OCSP_NO_CHECK: "OCSP No Check",  # RFC 2560 does not really define a spelling
        ExtensionOID.POLICY_CONSTRAINTS: "Policy Constraints",
        ExtensionOID.POLICY_MAPPINGS: "Policy Mappings",
        ExtensionOID.PRECERT_POISON: "Precert Poison",  # RFC 7633
        ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS: "Precertificate Signed Certificate Timestamps",  # RFC 7633  # NOQA: E501
        ExtensionOID.SIGNED_CERTIFICATE_TIMESTAMPS: "Signed Certificate Timestamps",  # RFC 7633
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME: "Subject Alternative Name",
        ExtensionOID.SUBJECT_DIRECTORY_ATTRIBUTES: "Subject Directory Attributes",
        ExtensionOID.SUBJECT_INFORMATION_ACCESS: "Subject Information Access",
        ExtensionOID.SUBJECT_KEY_IDENTIFIER: "Subject Key Identifier",
        ExtensionOID.TLS_FEATURE: "TLS Feature",  # RFC 7633
    }
)

#: Map of ExtensionOIDs to an Integer describing the RFC number where the extension is defined.
EXTENSION_RFC_DEFINITION = MappingProxyType(
    defaultdict(
        lambda: 5280,
        {
            ExtensionOID.OCSP_NO_CHECK: 2560,
            ExtensionOID.TLS_FEATURE: 7633,
            ExtensionOID.PRECERT_POISON: 6962,
            ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS: 6962,
            ExtensionOID.SIGNED_CERTIFICATE_TIMESTAMPS: 6962,
        },
    )
)

#: Map for types of general names.
GENERAL_NAME_TYPES: MappingProxyType[GeneralNames, type[x509.GeneralName]] = MappingProxyType(
    {
        "email": x509.RFC822Name,
        "URI": x509.UniformResourceIdentifier,
        "IP": x509.IPAddress,
        "DNS": x509.DNSName,
        "RID": x509.RegisteredID,
        "dirName": x509.DirectoryName,
        "otherName": x509.OtherName,
    }
)
GENERAL_NAME_NAMES: MappingProxyType[type[x509.GeneralName], GeneralNames] = MappingProxyType(
    {v: k for k, v in GENERAL_NAME_TYPES.items()}
)

#: Map of hash algorithm types in cryptography to standard hash algorithm names.
#:
#: Keys are the types from :py:attr:`~django_ca.typehints.AllowedHashTypes`, values are the matching names
#: from :py:attr:`~django_ca.typehints.HashAlgorithms`.
HASH_ALGORITHM_NAMES: MappingProxyType[type[AllowedHashTypes], HashAlgorithms] = MappingProxyType(
    {
        hashes.SHA224: "SHA-224",
        hashes.SHA256: "SHA-256",
        hashes.SHA384: "SHA-384",
        hashes.SHA512: "SHA-512",
        hashes.SHA3_224: "SHA3/224",
        hashes.SHA3_256: "SHA3/256",
        hashes.SHA3_384: "SHA3/384",
        hashes.SHA3_512: "SHA3/512",
    }
)

#: Map of hash algorithm names to hash algorithm types (the inverse of
#: :py:attr:`~django_ca.constants.HASH_ALGORITHM_NAMES`).
HASH_ALGORITHM_TYPES: MappingProxyType[HashAlgorithms, type[AllowedHashTypes]] = MappingProxyType(
    {v: k for k, v in HASH_ALGORITHM_NAMES.items()}
)

#: Map of `kwargs` for :py:class:`~cg:cryptography.x509.KeyUsage` to names in RFC 5280.
KEY_USAGE_NAMES: MappingProxyType[KeyUsages, str] = MappingProxyType(
    {
        "crl_sign": "cRLSign",
        "data_encipherment": "dataEncipherment",
        "decipher_only": "decipherOnly",
        "digital_signature": "digitalSignature",
        "encipher_only": "encipherOnly",
        "key_agreement": "keyAgreement",
        "key_cert_sign": "keyCertSign",
        "key_encipherment": "keyEncipherment",
        "content_commitment": "nonRepudiation",  # http://marc.info/?t=107176106300005&r=1&w=2
    }
)

# Opposite of KEY_USAGE_NAMES
KEY_USAGE_PARAMETERS: MappingProxyType[str, KeyUsages] = MappingProxyType(
    {v: k for k, v in KEY_USAGE_NAMES.items()}
)

#: Map of LogEntryTypes to their serialized value.
LOG_ENTRY_TYPE_KEYS = MappingProxyType(
    {
        LogEntryType.PRE_CERTIFICATE: "precertificate",
        LogEntryType.X509_CERTIFICATE: "x509_certificate",
    }
)

# Human-readable names come from RFC 4519 except where noted
#: Map OID objects to IDs used in subject strings
NAME_OID_NAMES = MappingProxyType(
    {
        NameOID.BUSINESS_CATEGORY: "businessCategory",
        NameOID.COMMON_NAME: "commonName",
        NameOID.COUNTRY_NAME: "countryName",
        NameOID.DN_QUALIFIER: "dnQualifier",
        NameOID.DOMAIN_COMPONENT: "domainComponent",
        NameOID.EMAIL_ADDRESS: "emailAddress",  # not specified in RFC 4519
        NameOID.GENERATION_QUALIFIER: "generationQualifier",
        NameOID.GIVEN_NAME: "givenName",
        NameOID.INITIALS: "initials",  # new in cryptography==41
        NameOID.INN: "inn",  # undocumented
        NameOID.JURISDICTION_COUNTRY_NAME: "jurisdictionCountryName",
        NameOID.JURISDICTION_LOCALITY_NAME: "jurisdictionLocalityName",
        NameOID.JURISDICTION_STATE_OR_PROVINCE_NAME: "jurisdictionStateOrProvinceName",
        NameOID.LOCALITY_NAME: "localityName",
        NameOID.OGRN: "ogrn",  # undocumented
        NameOID.ORGANIZATIONAL_UNIT_NAME: "organizationalUnitName",
        NameOID.ORGANIZATION_NAME: "organizationName",
        x509.ObjectIdentifier("2.5.4.97"): "organizationIdentifier",
        NameOID.POSTAL_ADDRESS: "postalAddress",
        NameOID.POSTAL_CODE: "postalCode",
        NameOID.PSEUDONYM: "pseudonym",  # not specified in RFC 4519
        NameOID.SERIAL_NUMBER: "serialNumber",
        NameOID.SNILS: "snils",  # undocumented
        NameOID.STATE_OR_PROVINCE_NAME: "stateOrProvinceName",
        NameOID.STREET_ADDRESS: "street",
        NameOID.SURNAME: "surname",
        NameOID.TITLE: "title",
        NameOID.UNSTRUCTURED_NAME: "unstructuredName",  # not specified in RFC 4519
        NameOID.USER_ID: "uid",
        NameOID.X500_UNIQUE_IDENTIFIER: "x500UniqueIdentifier",
    }
)

# Sources for OIDs that can be duplicate:
# * https://www.ibm.com/docs/en/ibm-mq/7.5?topic=certificates-distinguished-names - OU and DC
# * multiple_ous cert from the test suite.
#
# WARNING: sync any updates here to model_settings.SettingsModel._check_name().
#: OIDs that can occur multiple times in a certificate
MULTIPLE_OIDS = (NameOID.DOMAIN_COMPONENT, NameOID.ORGANIZATIONAL_UNIT_NAME, NameOID.STREET_ADDRESS)

RFC4514_NAME_OVERRIDES = MappingProxyType(
    {
        k: v
        for k, v in NAME_OID_NAMES.items()
        if k
        not in (
            NameOID.COMMON_NAME,
            NameOID.LOCALITY_NAME,
            NameOID.STATE_OR_PROVINCE_NAME,
            NameOID.ORGANIZATION_NAME,
            NameOID.ORGANIZATIONAL_UNIT_NAME,
            NameOID.COUNTRY_NAME,
            NameOID.STREET_ADDRESS,
            NameOID.DOMAIN_COMPONENT,
            NameOID.USER_ID,
        )
    }
)


NAME_OID_SHORTCUTS = MappingProxyType(
    {
        NameOID.COMMON_NAME: "CN",
        NameOID.COUNTRY_NAME: "C",
        NameOID.DOMAIN_COMPONENT: "DC",
        NameOID.LOCALITY_NAME: "L",
        NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
        NameOID.ORGANIZATION_NAME: "O",
        NameOID.STATE_OR_PROVINCE_NAME: "ST",
        NameOID.SURNAME: "SN",
    }
)

# Internal constant with full display names if there is a shortcut, e.g. "commonName (C)"
NAME_OID_DISPLAY_NAMES = MappingProxyType(
    {
        k: (f"{v} ({NAME_OID_SHORTCUTS[k]})" if k in NAME_OID_SHORTCUTS else v)
        for k, v in NAME_OID_NAMES.items()
    }
)

#: Map NameOID names to cryptography NameOID objects. This variant adds all RFC 4519 aliases as well.
NAME_OID_TYPES = MappingProxyType(
    {
        **{v: k for k, v in NAME_OID_NAMES.items()},
        **{
            "CN": NameOID.COMMON_NAME,
            "C": NameOID.COUNTRY_NAME,
            "DC": NameOID.DOMAIN_COMPONENT,
            "L": NameOID.LOCALITY_NAME,
            "O": NameOID.ORGANIZATION_NAME,
            "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
            "ST": NameOID.STATE_OR_PROVINCE_NAME,
            "streetAddress": NameOID.STREET_ADDRESS,  # not specified in RFC 4519, but consistent with others
            "SN": NameOID.SURNAME,
            "userid": NameOID.USER_ID,
        },
    }
)

#: Names supported for parsing :py:class:`~cg:cryptography.x509.OtherName` values.
OTHER_NAME_TYPES: MappingProxyType[OtherNames, asn1crypto.core.Primitive] = MappingProxyType(
    {
        "UTF8String": asn1crypto.core.UTF8String,
        "UNIVERSALSTRING": asn1crypto.core.UniversalString,
        "IA5STRING": asn1crypto.core.IA5String,
        "BOOLEAN": asn1crypto.core.Boolean,
        "UTCTIME": asn1crypto.core.UTCTime,
        "GENERALIZEDTIME": asn1crypto.core.GeneralizedTime,
        "NULL": asn1crypto.core.Null,
        "INTEGER": asn1crypto.core.Integer,
        "OctetString": asn1crypto.core.OctetString,
    }
)

# Inverse of OTHER_NAME_TYPES
OTHER_NAME_NAMES: MappingProxyType[asn1crypto.core.Primitive, OtherNames] = MappingProxyType(
    {v: k for k, v in OTHER_NAME_TYPES.items()}
)

#: Aliases for parsing :py:class:`~cg:cryptography.x509.OtherName` values.
OTHER_NAME_ALIASES: MappingProxyType[str, OtherNames] = MappingProxyType(
    {
        "UTF8": "UTF8String",
        "UNIV": "UNIVERSALSTRING",
        "IA5": "IA5STRING",
        "BOOL": "BOOLEAN",
        "UTC": "UTCTIME",
        "GENTIME": "GENERALIZEDTIME",
        "INT": "INTEGER",
    }
)

#: Tuple of supported public key types.
PUBLIC_KEY_TYPES: tuple[type[CertificateIssuerPublicKeyTypes], ...] = (
    dsa.DSAPublicKey,
    ec.EllipticCurvePublicKey,
    ed25519.Ed25519PublicKey,
    ed448.Ed448PublicKey,
    rsa.RSAPublicKey,
)
PUBLIC_KEY_TYPE_MAPPING: MappingProxyType[ParsableKeyType, type[CertificateIssuerPublicKeyTypes]] = (
    MappingProxyType(
        {
            "DSA": dsa.DSAPublicKey,
            "EC": ec.EllipticCurvePublicKey,
            "Ed25519": ed25519.Ed25519PublicKey,
            "Ed448": ed448.Ed448PublicKey,
            "RSA": rsa.RSAPublicKey,
        }
    )
)


#: Tuple of supported private key types.
PRIVATE_KEY_TYPES: tuple[type[CertificateIssuerPrivateKeyTypes], ...] = (
    dsa.DSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey,
    rsa.RSAPrivateKey,
)
PARSABLE_KEY_TYPES: tuple["ParsableKeyType", ...] = ("RSA", "DSA", "EC", "Ed25519", "Ed448")

TLS_FEATURE_KEYS = MappingProxyType(
    {
        x509.TLSFeatureType.status_request: "status_request",
        x509.TLSFeatureType.status_request_v2: "status_request_v2",
    }
)

#: Map of human-readable names/serialized values to :py:class:`~cg:cryptography.x509.TLSFeatureType` members.
TLS_FEATURE_NAMES = MappingProxyType(
    {
        # https://tools.ietf.org/html/rfc6066.html:
        "status_request": x509.TLSFeatureType.status_request,
        "OCSPMustStaple": x509.TLSFeatureType.status_request,
        # https://tools.ietf.org/html/rfc6961.html (not commonly used):
        "MultipleCertStatusRequest": x509.TLSFeatureType.status_request_v2,
        "status_request_v2": x509.TLSFeatureType.status_request_v2,
    }
)


class ReasonFlags(enum.Enum):
    """An enumeration for CRL reasons.

    This enumeration is a copy of ``cryptography.x509.ReasonFlags``. We create a copy because any change
    in the enumeration would trigger a database migration, so up/downgrading cryptography might cause problems
    with your Django project.
    """

    unspecified = "unspecified"
    key_compromise = "keyCompromise"
    ca_compromise = "cACompromise"
    affiliation_changed = "affiliationChanged"
    superseded = "superseded"
    cessation_of_operation = "cessationOfOperation"
    certificate_hold = "certificateHold"
    privilege_withdrawn = "privilegeWithdrawn"
    aa_compromise = "aACompromise"
    remove_from_crl = "removeFromCRL"


#: Mapping of RFC 5280, section 5.3.1 reason codes too cryptography reason codes
REASON_CODES = {
    0: ReasonFlags.unspecified,
    1: ReasonFlags.key_compromise,
    2: ReasonFlags.ca_compromise,
    3: ReasonFlags.affiliation_changed,
    4: ReasonFlags.superseded,
    5: ReasonFlags.cessation_of_operation,
    6: ReasonFlags.certificate_hold,
    8: ReasonFlags.remove_from_crl,
    9: ReasonFlags.privilege_withdrawn,
    10: ReasonFlags.aa_compromise,
}

#: Mapping of ReasonFlags to human-readable strings
REVOCATION_REASONS = (
    (ReasonFlags.aa_compromise.name, _("Attribute Authority compromised")),
    (ReasonFlags.affiliation_changed.name, _("Affiliation changed")),
    (ReasonFlags.ca_compromise.name, _("CA compromised")),
    (ReasonFlags.certificate_hold.name, _("On Hold")),
    (ReasonFlags.cessation_of_operation.name, _("Cessation of operation")),
    (ReasonFlags.key_compromise.name, _("Key compromised")),
    (ReasonFlags.privilege_withdrawn.name, _("Privilege withdrawn")),
    (ReasonFlags.remove_from_crl.name, _("Removed from CRL")),
    (ReasonFlags.superseded.name, _("Superseded")),
    (ReasonFlags.unspecified.name, _("Unspecified")),
)
