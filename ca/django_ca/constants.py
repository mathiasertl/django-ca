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

from cryptography.x509.oid import ExtensionOID

from django.utils.translation import gettext_lazy as _


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

#: Map Object Identifiers to human readable names as they appear in the RFC where they are defined.
OID_TO_EXTENSION_NAMES = {
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
