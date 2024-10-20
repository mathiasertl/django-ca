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

"""Test migration helpers."""

from typing import Optional

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID

import pytest

from django_ca.migration_helpers import Migration0040Helper
from django_ca.models import CertificateAuthority
from django_ca.tests.base.utils import distribution_point, dns, rdn, uri


@pytest.mark.parametrize(
    ("crl_url", "full_name"),
    (
        ("https://example.com", [uri("https://example.com")]),
        (
            "https://example.com\nhttps://example.net",
            [uri("https://example.com"), uri("https://example.net")],
        ),
        (
            "https://example.com \n\n https://example.net",  # more newlines and extra spaces
            [uri("https://example.com"), uri("https://example.net")],
        ),
    ),
)
def test_0040_crl_url_to_sign_crl_distribution_points(
    root: CertificateAuthority, crl_url: str, full_name: Optional[list[x509.GeneralName]]
) -> None:
    """Test migrating a populated `crl_url` field to `sign_crl_distribution_points`."""
    root.crl_url = crl_url  # type: ignore[attr-defined]  # what we're testing
    Migration0040Helper.crl_url_to_sign_crl_distribution_points(root)  # type: ignore[arg-type]
    dpoint = x509.DistributionPoint(full_name=full_name, relative_name=None, crl_issuer=None, reasons=None)
    ext = x509.Extension(
        oid=ExtensionOID.CRL_DISTRIBUTION_POINTS, critical=False, value=x509.CRLDistributionPoints([dpoint])
    )
    assert root.sign_crl_distribution_points == ext


@pytest.mark.parametrize(
    ("issuer_alt_name", "general_names"),
    (
        ("https://example.com", [uri("https://example.com")]),
        ("URI:https://example.com", [uri("https://example.com")]),
        # issuer_alt_name was a CharField, values where comma-separated.
        ("URI:https://example.com,DNS:example.net", [uri("https://example.com"), dns("example.net")]),
    ),
)
def test_0040_issuer_alt_name_to_sign_issuer_alternative_name(
    root: CertificateAuthority, issuer_alt_name: str, general_names: list[x509.GeneralName]
) -> None:
    """Test migrating the `issuer_alt_name` field to `sign_issuer_alternative_name`."""
    root.issuer_alt_name = issuer_alt_name  # type: ignore[attr-defined]  # what we're testing
    Migration0040Helper.issuer_alt_name_to_sign_issuer_alternative_name(root)  # type: ignore[arg-type]
    assert root.sign_issuer_alternative_name == x509.Extension(
        oid=ExtensionOID.ISSUER_ALTERNATIVE_NAME,
        critical=False,
        value=x509.IssuerAlternativeName(general_names),
    )


@pytest.mark.parametrize(
    ("issuer_url", "ocsp_url", "access_descriptions"),
    (
        (
            "https://issuer.example.com",
            "",
            [
                x509.AccessDescription(
                    access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                    access_location=uri("https://issuer.example.com"),
                )
            ],
        ),
        (
            "",
            "https://ocsp.example.com",
            [
                x509.AccessDescription(
                    access_method=AuthorityInformationAccessOID.OCSP,
                    access_location=uri("https://ocsp.example.com"),
                )
            ],
        ),
        (
            "https://issuer.example.com",
            "https://ocsp.example.com",
            [
                x509.AccessDescription(
                    access_method=AuthorityInformationAccessOID.OCSP,
                    access_location=uri("https://ocsp.example.com"),
                ),
                x509.AccessDescription(
                    access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                    access_location=uri("https://issuer.example.com"),
                ),
            ],
        ),
    ),
)
def test_0040_ocsp_url_and_issuer_url_to_sign_authority_information_access(
    root: CertificateAuthority,
    issuer_url: str,
    ocsp_url: str,
    access_descriptions: list[x509.AccessDescription],
) -> None:
    """Test migrating `issuer_url` and `ocsp_url` to `sign_authority_information_access`."""
    root.issuer_url = issuer_url  # type: ignore[attr-defined]  # what we're testing
    root.ocsp_url = ocsp_url  # type: ignore[attr-defined]  # what we're testing
    Migration0040Helper.ocsp_url_and_issuer_url_to_sign_authority_information_access(
        root  # type: ignore[arg-type]
    )
    assert root.sign_authority_information_access == x509.Extension(
        oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
        critical=False,
        value=x509.AuthorityInformationAccess(access_descriptions),
    )


@pytest.mark.parametrize(
    ("distribution_points", "crl_url"),
    (
        ([distribution_point([uri("https://example.com")])], "https://example.com"),
        (
            [distribution_point([uri("https://example.com"), uri("https://example.net")])],
            "https://example.com\nhttps://example.net",
        ),
        (  # one DP with a relative name
            [distribution_point(relative_name=rdn([(NameOID.COMMON_NAME, "example.com")]))],
            "",
        ),
        (  # two DPs with a relative name each
            [
                distribution_point(relative_name=rdn([(NameOID.COMMON_NAME, "example.com")])),
                distribution_point(relative_name=rdn([(NameOID.COMMON_NAME, "example.net")])),
            ],
            "",
        ),
        (  # second DP has a full name, but no URI
            [
                distribution_point(relative_name=rdn([(NameOID.COMMON_NAME, "example.com")])),
                distribution_point([dns("example.com")]),
            ],
            "",
        ),
        (  # second DP has a full name, with two URIs in between. Third DP is ignored.
            [
                distribution_point(relative_name=rdn([(NameOID.COMMON_NAME, "example.com")])),
                distribution_point(
                    [
                        dns("example.com"),
                        uri("https://example.com"),
                        dns("example.net"),
                        uri("https://example.net"),
                    ]
                ),
                distribution_point([uri("https://example.com")]),
            ],
            "https://example.com\nhttps://example.net",
        ),
    ),
)
def test_0040_backwards_sign_crl_distribution_points_to_crl_url(
    root: CertificateAuthority, distribution_points: list[x509.DistributionPoint], crl_url: str
) -> None:
    """Test backwards-migrating a populated `sign_crl_distribution_points` field to `crl_url`."""
    root.sign_crl_distribution_points = x509.Extension(
        oid=ExtensionOID.CRL_DISTRIBUTION_POINTS,
        critical=False,
        value=x509.CRLDistributionPoints(distribution_points),
    )
    Migration0040Helper.backwards_sign_crl_distribution_points_to_crl_url(root)  # type: ignore[arg-type]
    assert root.crl_url == crl_url  # type: ignore[attr-defined]  # what we're testing


@pytest.mark.parametrize(
    ("issuer_alt_name", "general_names"),
    (
        ("URI:https://example.com", [uri("https://example.com")]),
        # issuer_alt_name was a CharField, values where comma-separated.
        ("URI:https://example.com,DNS:example.net", [uri("https://example.com"), dns("example.net")]),
    ),
)
def test_0040_backwards_sign_issuer_alternative_name_to_issuer_url(
    root: CertificateAuthority, issuer_alt_name: str, general_names: list[x509.GeneralName]
) -> None:
    """Test migrating the `issuer_alt_name` field to `sign_issuer_alternative_name`."""
    root.sign_issuer_alternative_name = x509.Extension(
        oid=ExtensionOID.ISSUER_ALTERNATIVE_NAME,
        critical=False,
        value=x509.IssuerAlternativeName(general_names),
    )
    Migration0040Helper.backwards_sign_issuer_alternative_name_to_issuer_url(root)  # type: ignore[arg-type]
    assert root.issuer_alt_name == issuer_alt_name  # type: ignore[attr-defined]  # what we're testing


@pytest.mark.parametrize(
    ("issuer_url", "ocsp_url", "access_descriptions"),
    (
        (
            "https://issuer.example.com",
            "",
            [
                x509.AccessDescription(
                    access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                    access_location=uri("https://issuer.example.com"),
                )
            ],
        ),
        (
            "",
            "https://ocsp.example.com",
            [
                x509.AccessDescription(
                    access_method=AuthorityInformationAccessOID.OCSP,
                    access_location=uri("https://ocsp.example.com"),
                )
            ],
        ),
        (
            "https://issuer.example.com",
            "https://ocsp.example.com",
            [
                x509.AccessDescription(
                    access_method=AuthorityInformationAccessOID.OCSP,
                    access_location=uri("https://ocsp.example.com"),
                ),
                x509.AccessDescription(
                    access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                    access_location=uri("https://issuer.example.com"),
                ),
            ],
        ),
    ),
)
def test_0040_backwards_sign_authority_information_access_to_ocsp_url_and_issuer_url(
    root: CertificateAuthority,
    issuer_url: str,
    ocsp_url: str,
    access_descriptions: list[x509.AccessDescription],
) -> None:
    """Test migrating `issuer_url` and `ocsp_url` to `sign_authority_information_access`."""
    root.sign_authority_information_access = x509.Extension(
        oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
        critical=False,
        value=x509.AuthorityInformationAccess(access_descriptions),
    )

    Migration0040Helper.backwards_sign_authority_information_access_to_ocsp_url_and_issuer_url(
        root  # type: ignore[arg-type]
    )
    assert root.issuer_url == issuer_url  # type: ignore[attr-defined]  # what we're testing
    assert root.ocsp_url == ocsp_url  # type: ignore[attr-defined]  # what we're testing


def test_0040_empty_migration_for_0040(root: CertificateAuthority) -> None:
    """Test forward migrations with empty crl_url/issuer_url and ocsp_url."""
    root.crl_url = ""  # type: ignore[attr-defined]  # what we're testing
    root.issuer_alt_name = ""  # type: ignore[attr-defined]  # what we're testing
    root.issuer_url = ""  # type: ignore[attr-defined]  # what we're testing
    root.ocsp_url = ""  # type: ignore[attr-defined]  # what we're testing

    Migration0040Helper.crl_url_to_sign_crl_distribution_points(root)  # type: ignore[arg-type]
    Migration0040Helper.issuer_alt_name_to_sign_issuer_alternative_name(root)  # type: ignore[arg-type]
    Migration0040Helper.ocsp_url_and_issuer_url_to_sign_authority_information_access(
        root  # type: ignore[arg-type]
    )

    assert root.sign_authority_information_access is None
    assert root.sign_crl_distribution_points is None
    assert root.sign_issuer_alternative_name is None


def test_0040_empty_backwards_migration_for_0040(root: CertificateAuthority) -> None:
    """Test forward migrations with empty crl_url/issuer_url and ocsp_url."""
    root.sign_authority_information_access = None
    root.sign_crl_distribution_points = None
    root.sign_issuer_alternative_name = None

    Migration0040Helper.backwards_sign_crl_distribution_points_to_crl_url(root)  # type: ignore[arg-type]
    Migration0040Helper.backwards_sign_issuer_alternative_name_to_issuer_url(root)  # type: ignore[arg-type]
    Migration0040Helper.backwards_sign_authority_information_access_to_ocsp_url_and_issuer_url(
        root  # type: ignore[arg-type]
    )

    assert root.crl_url == ""  # type: ignore[attr-defined]  # what we're testing
    assert root.ocsp_url == ""  # type: ignore[attr-defined]  # what we're testing
    assert root.issuer_url == ""  # type: ignore[attr-defined]  # what we're testing
    assert root.issuer_alt_name == ""  # type: ignore[attr-defined]  # what we're testing
