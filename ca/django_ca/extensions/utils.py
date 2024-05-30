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

"""``django_ca.extensions.utils`` contains various utility classes used by X.509 extensions."""

import typing
from collections.abc import Iterator
from typing import Any, Optional, Union

from cryptography import x509
from cryptography.x509.certificate_transparency import LogEntryType, SignedCertificateTimestamp
from cryptography.x509.oid import ExtensionOID

from django.template.loader import render_to_string
from django.urls import reverse

from django_ca.constants import KEY_USAGE_NAMES
from django_ca.typehints import (
    CertificateExtension,
    CertificateExtensionDict,
    ConfigurableExtensionDict,
    EndEntityCertificateExtensionDict,
)
from django_ca.utils import add_colons, bytes_to_hex, int_to_hex


def extension_as_admin_html(
    extension: CertificateExtension, extra_context: Optional[dict[str, Any]] = None
) -> str:
    """Convert an extension to HTML code suitable for the admin interface."""
    template = f"django_ca/admin/extensions/{extension.oid.dotted_string}.html"
    if isinstance(extension.value, x509.UnrecognizedExtension):
        template = "django_ca/admin/extensions/unrecognized_extension.html"

    context = {"extension": extension, "x509": x509}
    if extra_context is not None:
        context.update(extra_context)

    return render_to_string(template, context=context)


def certificate_policies_is_simple(value: x509.CertificatePolicies) -> bool:
    """Check if a Certificate Policies extension is "simple".

    The extension is considered simple if it contains a single Policy Information, and that policy information
    contains no notice references and at most one explicit text.
    """
    if len(value) > 1:
        return False

    policy_information = value[0]
    has_explicit_text = False

    if not policy_information.policy_qualifiers:
        return True

    for policy_qualifier in policy_information.policy_qualifiers:
        if isinstance(policy_qualifier, str):
            continue  # we support multiple - no need to keep track

        if policy_qualifier.notice_reference:
            return False
        if has_explicit_text:
            return False
        has_explicit_text = True
    return True


def key_usage_items(value: x509.KeyUsage) -> Iterator[str]:
    """Get a list of basic key usages."""
    for attr, name in KEY_USAGE_NAMES.items():
        try:
            if getattr(value, attr):
                yield name
        except ValueError:
            # x509.KeyUsage raises ValueError on some attributes to ensure consistency
            pass


def signed_certificate_timestamp_values(sct: SignedCertificateTimestamp) -> tuple[str, str, str, str]:
    """Get values from a SignedCertificateTimestamp as a tuple of strings."""
    if sct.entry_type == LogEntryType.PRE_CERTIFICATE:
        entry_type = "Precertificate"
    elif sct.entry_type == LogEntryType.X509_CERTIFICATE:  # pragma: no cover  # Unseen in the wild
        entry_type = "x509 certificate"
    else:  # pragma: no cover  # We support everything that has been specified so far
        entry_type = "unknown"
    return entry_type, sct.version.name, bytes_to_hex(sct.log_id), sct.timestamp.isoformat(" ")


def get_formatting_context(serial: int, signer_serial: int) -> dict[str, Union[int, str]]:
    """Get the context for formatting extensions."""
    hex_serial = int_to_hex(serial)
    signer_serial_hex = int_to_hex(signer_serial)
    return {
        "SERIAL": serial,
        "SERIAL_HEX": hex_serial,
        "SERIAL_HEX_COLONS": add_colons(hex_serial),
        "SIGNER_SERIAL": signer_serial,
        "SIGNER_SERIAL_HEX": signer_serial_hex,
        "SIGNER_SERIAL_HEX_COLONS": add_colons(signer_serial_hex),
        "CA_ISSUER_PATH": reverse("django_ca:issuer", kwargs={"serial": signer_serial_hex}).lstrip("/"),
    }


def format_general_name(name: x509.GeneralName, context: dict[str, Union[str, int]]) -> x509.GeneralName:
    """Format a general name (currently only operating on UniformResourceIdentifier)."""
    if isinstance(name, x509.UniformResourceIdentifier):
        return x509.UniformResourceIdentifier(name.value.format(**context))
    return name


def format_extensions(
    # NOTE: dicts are invariant in mypy, so the type of the dict when calling this function needs to *exactly*
    #   match. That's why we typehint an essentially redundant union for extensions so that any of the types
    #   can be used.
    extensions: Union[ConfigurableExtensionDict, EndEntityCertificateExtensionDict, CertificateExtensionDict],
    context: dict[str, Union[str, int]],
) -> None:
    """Format extensions based on the given context."""
    if ExtensionOID.AUTHORITY_INFORMATION_ACCESS in extensions:
        authority_information_access = typing.cast(
            x509.Extension[x509.AuthorityInformationAccess],
            extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
        )

        access_descriptions = [
            x509.AccessDescription(
                access_method=ad.access_method,
                access_location=format_general_name(ad.access_location, context),
            )
            for ad in authority_information_access.value
        ]
        extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS] = x509.Extension(
            oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
            critical=authority_information_access.critical,
            value=x509.AuthorityInformationAccess(access_descriptions),
        )

    if ExtensionOID.CRL_DISTRIBUTION_POINTS in extensions:
        crl_distribution_points = typing.cast(
            x509.Extension[x509.CRLDistributionPoints],
            extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS],
        )

        distribution_points: list[x509.DistributionPoint] = []

        distribution_point: x509.DistributionPoint
        for distribution_point in crl_distribution_points.value:
            if distribution_point.full_name is None:
                distribution_points.append(distribution_point)
            else:
                names = [format_general_name(name, context) for name in distribution_point.full_name]
                distribution_points.append(
                    x509.DistributionPoint(
                        full_name=names,
                        relative_name=None,
                        reasons=distribution_point.reasons,
                        crl_issuer=distribution_point.crl_issuer,
                    )
                )

        extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS] = x509.Extension(
            oid=ExtensionOID.CRL_DISTRIBUTION_POINTS,
            critical=crl_distribution_points.critical,
            value=x509.CRLDistributionPoints(distribution_points),
        )
