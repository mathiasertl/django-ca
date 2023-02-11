# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca.  If not,
# see <http://www.gnu.org/licenses/>.

"""Collection of constants used by django-ca."""

import enum
from collections import defaultdict
from types import MappingProxyType
from typing import Type

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.certificate_transparency import LogEntryType
from cryptography.x509.oid import ExtendedKeyUsageOID as _ExtendedKeyUsageOID
from cryptography.x509.oid import ExtensionOID

from django.utils.translation import gettext_lazy as _

#: Mapping of canonical elliptic curve names (lower-cased) to the implementing classes
ELLIPTIC_CURVE_NAMES: "MappingProxyType[str, Type[ec.EllipticCurve]]" = MappingProxyType(
    {
        ec.SECT571R1.name.lower(): ec.SECT571R1,
        ec.SECT409R1.name.lower(): ec.SECT409R1,
        ec.SECT283R1.name.lower(): ec.SECT283R1,
        ec.SECT233R1.name.lower(): ec.SECT233R1,
        ec.SECT163R2.name.lower(): ec.SECT163R2,
        ec.SECT571K1.name.lower(): ec.SECT571K1,
        ec.SECT409K1.name.lower(): ec.SECT409K1,
        ec.SECT283K1.name.lower(): ec.SECT283K1,
        ec.SECT233K1.name.lower(): ec.SECT233K1,
        ec.SECT163K1.name.lower(): ec.SECT163K1,
        ec.SECP521R1.name.lower(): ec.SECP521R1,
        ec.SECP384R1.name.lower(): ec.SECP384R1,
        ec.SECP256R1.name.lower(): ec.SECP256R1,
        ec.SECP256K1.name.lower(): ec.SECP256K1,
        ec.SECP224R1.name.lower(): ec.SECP224R1,
        ec.SECP192R1.name.lower(): ec.SECP192R1,
        ec.BrainpoolP256R1.name.lower(): ec.BrainpoolP256R1,
        ec.BrainpoolP384R1.name.lower(): ec.BrainpoolP384R1,
        ec.BrainpoolP512R1.name.lower(): ec.BrainpoolP512R1,
    }
)


class ExtendedKeyUsageOID(_ExtendedKeyUsageOID):
    """Extend the OIDs known to cryptography with what users needed over the years."""

    # Defined in RFC 3280, occurs in TrustID Server A52 CA
    IPSEC_END_SYSTEM = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.5")
    IPSEC_TUNNEL = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.6")
    IPSEC_USER = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.7")

    # Used by PKINIT logon on Windows (see  github#46)
    SMARTCARD_LOGON = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.2")

    # mobilee Driving Licence or mDL (see ISO/IEC DIS 18013-5, GitHub PR #81)
    MDL_DOCUMENT_SIGNER = x509.ObjectIdentifier("1.0.18013.5.1.2")
    MDL_JWS_CERTIFICATE = x509.ObjectIdentifier("1.0.18013.5.1.3")

    # ExtendedKeyUsageOID.CERTIFICATE_TRANSPARENCY was added in cryptography==39.0
    # once support for cryptography<39.0 is dropped.
    if not hasattr(_ExtendedKeyUsageOID, "CERTIFICATE_TRANSPARENCY"):  # pragma: cryptography<38.0 branch
        CERTIFICATE_TRANSPARENCY = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.4")


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
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME: _("SHOULD mark this extension as non-critical"),
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
        ExtensionOID.TLS_FEATURE: False,  # RFC 7633: MUST NOT be marked critical
    }
)

#: Map of ExtensionOIDs to keys that are usable as class attributes.
EXTENSION_KEYS = MappingProxyType(
    {
        ExtensionOID.AUTHORITY_INFORMATION_ACCESS: "authority_information_access",
        ExtensionOID.AUTHORITY_KEY_IDENTIFIER: "authority_key_identifier",
        ExtensionOID.BASIC_CONSTRAINTS: "basic_constraints",
        ExtensionOID.CERTIFICATE_POLICIES: "certificate_policies",
        ExtensionOID.CRL_DISTRIBUTION_POINTS: "crl_distribution_points",
        ExtensionOID.CRL_NUMBER: "crl_number",
        ExtensionOID.DELTA_CRL_INDICATOR: "delta_crl_indicator",
        ExtensionOID.EXTENDED_KEY_USAGE: "extended_key_usage",
        ExtensionOID.FRESHEST_CRL: "freshest_crl",
        ExtensionOID.INHIBIT_ANY_POLICY: "inhibit_any_policy",
        ExtensionOID.ISSUER_ALTERNATIVE_NAME: "issuer_alternative_name",
        ExtensionOID.ISSUING_DISTRIBUTION_POINT: "issuing_distribution_point",
        ExtensionOID.KEY_USAGE: "key_usage",
        ExtensionOID.NAME_CONSTRAINTS: "name_constraints",
        ExtensionOID.OCSP_NO_CHECK: "ocsp_no_check",  # RFC 2560 does not really define a spelling
        ExtensionOID.POLICY_CONSTRAINTS: "policy_constraints",
        ExtensionOID.POLICY_MAPPINGS: "policy_mappings",
        ExtensionOID.PRECERT_POISON: "precert_poison",  # RFC 7633
        ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS: "precertificate_signed_certificate_timestamps",  # RFC 7633  # NOQA: E501
        ExtensionOID.SIGNED_CERTIFICATE_TIMESTAMPS: "signed_certificate_timestamps",  # RFC 7633
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME: "subject_alternative_name",
        ExtensionOID.SUBJECT_DIRECTORY_ATTRIBUTES: "subject_directory_attributes",
        ExtensionOID.SUBJECT_INFORMATION_ACCESS: "subject_information_access",
        ExtensionOID.SUBJECT_KEY_IDENTIFIER: "subject_key_identifier",
        ExtensionOID.TLS_FEATURE: "tls_feature",  # RFC 7633
    }
)

#: Map of extension keys to ExtensionOIDs (the inverse of EXTENSION_KEYS).
EXTENSION_KEY_OIDS = MappingProxyType({v: k for k, v in EXTENSION_KEYS.items()})

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


# pragma: only django-ca<1.25.0  # support for non-standard hash algorithm names is droped in 1.25.0
HASH_ALGORITHM_KEYS: "MappingProxyType[Type[hashes.HashAlgorithm], str]" = MappingProxyType(
    {
        # NOTE: shake128, shake256, blake2b and blake2s need a digest size, which is not currently supported
        hashes.SHA512_224: hashes.SHA512_224.name,
        hashes.SHA512_256: hashes.SHA512_256.name,
        hashes.SHA224: hashes.SHA224.name,
        hashes.SHA256: hashes.SHA256.name,
        hashes.SHA384: hashes.SHA384.name,
        hashes.SHA512: hashes.SHA512.name,
        hashes.SHA3_224: hashes.SHA3_224.name,
        hashes.SHA3_256: hashes.SHA3_256.name,
        hashes.SHA3_384: hashes.SHA3_384.name,
        hashes.SHA3_512: hashes.SHA3_512.name,
        # hashes.SHAKE128: hashes.SHAKE128.name,
        # hashes.SHAKE256: hashes.SHAKE256.name,
        # hashes.BLAKE2b: hashes.BLAKE2b.name,
        # hashes.BLAKE2s: hashes.BLAKE2s.name,
        hashes.SM3: hashes.SM3.name,
    }
)

# pragma: only django-ca<1.25.0  # support for non-standard hash algorithm names is droped in 1.25.0
HASH_ALGORITHM_KEY_TYPES: "MappingProxyType[str, Type[hashes.HashAlgorithm]]" = MappingProxyType(
    {v: k for k, v in HASH_ALGORITHM_KEYS.items()}
)

#: Map of hash algorithm types in cryptography to standard hash algorithm names. The values can be used for
#: ``--algorithm`` command line parameter.
HASH_ALGORITHM_NAMES: "MappingProxyType[Type[hashes.HashAlgorithm], str]" = MappingProxyType(
    {
        # NOTE: shake128, shake256, blake2b and blake2s need a digest size, which is not currently supported
        hashes.SHA512_224: "SHA-512/224",
        hashes.SHA512_256: "SHA-512/256",
        hashes.SHA224: "SHA-224",
        hashes.SHA256: "SHA-256",
        hashes.SHA384: "SHA-384",
        hashes.SHA512: "SHA-512",
        hashes.SHA3_224: "SHA3/224",
        hashes.SHA3_256: "SHA3/256",
        hashes.SHA3_384: "SHA3/384",
        hashes.SHA3_512: "SHA3/512",
        # hashes.SHAKE128: hashes.SHAKE128.name,
        # hashes.SHAKE256: hashes.SHAKE256.name,
        # hashes.BLAKE2b: hashes.BLAKE2b.name,
        # hashes.BLAKE2s: hashes.BLAKE2s.name,
        hashes.SM3: "SM3",
    }
)
#: Mapping of hash algorithm names to hash algorithm types (the inverse of HASH_ALGORITHM_NAMES).
HASH_ALGORITHM_TYPES: "MappingProxyType[str, Type[hashes.HashAlgorithm]]" = MappingProxyType(
    {v: k for k, v in HASH_ALGORITHM_NAMES.items()}
)

#: Map of `kwargs` for :py:class:`~cg:cryptography.x509.KeyUsage` to names in RFC 5280.
KEY_USAGE_NAMES = MappingProxyType(
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


#: Map of LogEntryTypes to their serialized value.
LOG_ENTRY_TYPE_KEYS = MappingProxyType(
    {
        LogEntryType.PRE_CERTIFICATE: "precertificate",
        LogEntryType.X509_CERTIFICATE: "x509_certificate",
    }
)

#: Tuple of supported public key types.
PUBLIC_KEY_TYPES = (
    dsa.DSAPublicKey,
    ec.EllipticCurvePublicKey,
    ed25519.Ed25519PublicKey,
    ed448.Ed448PublicKey,
    rsa.RSAPublicKey,
)

#: Tuple of supported private key types.
PRIVATE_KEY_TYPES = (
    dsa.DSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey,
    rsa.RSAPrivateKey,
)
PARSABLE_KEY_TYPES = ("RSA", "DSA", "EC", "Ed25519", "Ed448")

#: Map of human-readable names/serialized values to TLSFeatureTypes.
TLS_FEATURE_NAMES = MappingProxyType(
    {
        # https://tools.ietf.org/html/rfc6066.html:
        "OCSPMustStaple": x509.TLSFeatureType.status_request,
        "status_request": x509.TLSFeatureType.status_request,
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
