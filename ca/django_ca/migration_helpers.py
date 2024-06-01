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

"""Helper functions for data migrations.

This module collects functions that are used in data migrations. The functions are moved here to make sure
that they are tested properly.
"""

import typing
import warnings
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from django_ca.utils import format_general_name, parse_general_name, split_str


class Migration0040Helper:
    """Helper for migration 0040."""

    class MigratingCertificateAuthority(typing.Protocol):
        """Type hinting protocol for a Certificate Authority as it appears in migration 0040."""

        crl_url: str
        issuer_url: str
        ocsp_url: str
        issuer_alt_name: str
        sign_authority_information_access: Optional[x509.Extension[x509.AuthorityInformationAccess]]
        sign_crl_distribution_points: Optional[x509.Extension[x509.CRLDistributionPoints]]
        sign_issuer_alternative_name: Optional[x509.Extension[x509.IssuerAlternativeName]]

    @staticmethod
    def crl_url_to_sign_crl_distribution_points(ca: MigratingCertificateAuthority) -> None:
        """Migrate the `crl_url` field to the `sign_crl_distribution_points` field.

        The `crl_url` field was a TextField with blank=True and using a multiline_url_validator. The value was
        thus validated to be a string with one URL per line. The `sign_crl_distribution_points` field is a
        `django_ca.modelfields.CRLDistributionPointsField` field.
        """
        # This is how crl_url was parsed until 1.27.0 (NOTE: lines were validated to be URLs).
        lines = [line.strip() for line in ca.crl_url.splitlines()]
        full_name = [x509.UniformResourceIdentifier(line.strip()) for line in lines if line]
        if not full_name:
            ca.sign_crl_distribution_points = None
            return

        distribution_point = x509.DistributionPoint(
            full_name=full_name, relative_name=None, crl_issuer=None, reasons=None
        )
        ca.sign_crl_distribution_points = x509.Extension(
            oid=ExtensionOID.CRL_DISTRIBUTION_POINTS,
            critical=False,
            value=x509.CRLDistributionPoints([distribution_point]),
        )

    @staticmethod
    def issuer_alt_name_to_sign_issuer_alternative_name(ca: MigratingCertificateAuthority) -> None:
        """Migrate the `issuer_alt_name` field to the `sign_issuer_alternative_name` field.

        The `issuer_alt_name` field is a CharField with a max_length of 255 and no additional validators. The
        admin interface and command-line made sure that the value was a parsable general name. The
        `sign_issuer_alternative_name` field is a `django_ca.modelfields.IssuerAlternativeNameField`.
        """
        # This is how this value was parsed until 1.27.0. De facto, it was a single text input field, and
        # no documented input method (admin or command-line interface) allowed multiple values. The
        # maximum length was only 255 characters. Together, this makes multiple values unlikely.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            alternative_names = [
                parse_general_name(name) for name in split_str(ca.issuer_alt_name.strip(), ",")
            ]

        if not alternative_names:
            ca.sign_issuer_alternative_name = None
            return

        ca.sign_issuer_alternative_name = x509.Extension(
            oid=ExtensionOID.ISSUER_ALTERNATIVE_NAME,
            critical=False,
            value=x509.IssuerAlternativeName(alternative_names),
        )

    @staticmethod
    def ocsp_url_and_issuer_url_to_sign_authority_information_access(
        ca: MigratingCertificateAuthority,
    ) -> None:
        """Migrate the `ocsp_url` and `issuer_url` fields to the `sign_authority_information_access` field.

        The `ocsp_url` and `issuer_url` fields where both a URLField with blank=True. The
        `sign_authority_information_access` field is a
        `django_ca.modelfields.AuthorityInformationAccessField`.
        """
        ca.sign_authority_information_access = None
        ocsp_url = ca.ocsp_url.strip()
        issuer_url = ca.issuer_url.strip()

        access_descriptions = []
        if ocsp_url:
            access_descriptions.append(
                x509.AccessDescription(
                    access_method=AuthorityInformationAccessOID.OCSP,
                    access_location=x509.UniformResourceIdentifier(ocsp_url),
                )
            )
        if issuer_url:
            access_descriptions.append(
                x509.AccessDescription(
                    access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                    access_location=x509.UniformResourceIdentifier(issuer_url),
                )
            )
        if access_descriptions:
            ca.sign_authority_information_access = x509.Extension(
                oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
                critical=False,
                value=x509.AuthorityInformationAccess(access_descriptions),
            )

    @staticmethod
    def backwards_sign_crl_distribution_points_to_crl_url(ca: MigratingCertificateAuthority) -> None:
        """Backwards-migrate the `sign_issuer_alternative_name` to the `crl_url` field.

        .. NOTE:: This is **not** a lossless migration.

        This will join all URIs of the first Distribution Point that has any URIs. Any Distribution Point
        without a full name or without URIs are ignored. Any Distribution Point after the first one that has
        a URI is also ignored.
        """
        ca.crl_url = ""
        if ca.sign_crl_distribution_points is None:
            return

        # Field in 1.27.0 used a multiline URL validator, so values where always URLs (without prefix).
        distribution_point: Optional[x509.DistributionPoint] = next(
            (
                dp
                for dp in ca.sign_crl_distribution_points.value
                if dp.full_name is not None
                and any(isinstance(gn, x509.UniformResourceIdentifier) for gn in dp.full_name)
            ),
            None,
        )
        if distribution_point is None:
            return

        # TYPEHINT NOTE: distribution_point.full_name == None is ruled out in next() above
        ca.crl_url = "\n".join(
            [
                name.value
                for name in distribution_point.full_name  # type: ignore[union-attr]
                if isinstance(name, x509.UniformResourceIdentifier)
            ]
        )

    @staticmethod
    def backwards_sign_issuer_alternative_name_to_issuer_url(ca: MigratingCertificateAuthority) -> None:
        """Backwards-migrate the `sign_issuer_alternative_name` to the `issuer_alt_name` field."""
        ca.issuer_alt_name = ""
        if ca.sign_issuer_alternative_name is None:
            return

        alternative_names = [format_general_name(name) for name in ca.sign_issuer_alternative_name.value]
        ca.issuer_alt_name = ",".join(alternative_names)

    @staticmethod
    def backwards_sign_authority_information_access_to_ocsp_url_and_issuer_url(
        ca: MigratingCertificateAuthority,
    ) -> None:
        """Backwards-migrate `sign_authority_information_access` field to `ocsp_url`/`issuer_url` fields."""
        ca.issuer_url = ""
        ca.ocsp_url = ""

        if ca.sign_authority_information_access is None:
            return

        descriptions: list[x509.AccessDescription] = list(ca.sign_authority_information_access.value)

        # Since the target fields are URL fields, we only consider x509.UniformResourceIdentifier instances.
        descriptions = [
            ad for ad in descriptions if isinstance(ad.access_location, x509.UniformResourceIdentifier)
        ]

        # Get OCSP descriptions
        ocsp_descriptions = [
            ad for ad in descriptions if ad.access_method == AuthorityInformationAccessOID.OCSP
        ]
        if ocsp_descriptions:
            ca.ocsp_url = ocsp_descriptions[0].access_location.value

        # Get CA Issuer descriptions
        issuer_descriptions = [
            ad for ad in descriptions if ad.access_method == AuthorityInformationAccessOID.CA_ISSUERS
        ]
        if issuer_descriptions:
            ca.issuer_url = issuer_descriptions[0].access_location.value
