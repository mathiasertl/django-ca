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

"""Test basic views."""

# pylint: disable=redefined-outer-name  # because of test fixtures

from collections.abc import Iterator
from http import HTTPStatus

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

from django.core.cache import cache
from django.test import Client
from django.urls import include, path, re_path, reverse

import pytest
from pytest_django import DjangoAssertNumQueries
from pytest_django.fixtures import SettingsWrapper

from django_ca import constants
from django_ca.models import Certificate, CertificateAuthority, CertificateRevocationList
from django_ca.tests.base.assertions import assert_crl, assert_removed_in_230
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS
from django_ca.tests.base.utils import get_idp
from django_ca.views import CertificateRevocationListView

ROOT_SERIAL = CERT_DATA["root"]["serial"]

pytestmark = [
    pytest.mark.freeze_time(TIMESTAMPS["everything_valid"]),
    pytest.mark.usefixtures("clear_cache"),
    pytest.mark.urls(__name__),
]

app_name = "django_ca"
urlpatterns = [
    path("django_ca/", include("django_ca.urls")),  # needed for fixtures
    re_path(r"^crl/(?P<serial>[0-9A-F:]+)/$", CertificateRevocationListView.as_view(), name="default"),
    re_path(
        r"^crl/ca/(?P<serial>[0-9A-F:]+)/$",
        CertificateRevocationListView.as_view(only_contains_ca_certs=True),
        name="ca",
    ),
    re_path(
        r"^crl/user/(?P<serial>[0-9A-F:]+)/$",
        CertificateRevocationListView.as_view(only_contains_user_certs=True),
        name="user",
    ),
    re_path(
        r"^crl/reasons/(?P<serial>[0-9A-F:]+)/$",
        CertificateRevocationListView.as_view(only_some_reasons=frozenset([x509.ReasonFlags.key_compromise])),
        name="reasons",
    ),
    re_path(
        r"^adv/(?P<serial>[0-9A-F:]+)/$",
        CertificateRevocationListView.as_view(content_type="foo/bar", expires=321, type=Encoding.PEM),
        name="advanced",
    ),
    re_path(  # pragma: only django-ca<2.3.0
        r"^deprecated-full-scope/(?P<serial>[0-9A-F:]+)/$",
        CertificateRevocationListView.as_view(scope=None),
        name="deprecated-full-scope",
    ),
    re_path(  # pragma: only django-ca<2.3.0
        r"^deprecated-ca-scope/(?P<serial>[0-9A-F:]+)/$",
        CertificateRevocationListView.as_view(scope="ca"),
        name="deprecated-ca-scope",
    ),
    re_path(  # pragma: only django-ca<2.3.0
        r"^deprecated-user-scope/(?P<serial>[0-9A-F:]+)/$",
        CertificateRevocationListView.as_view(scope="user"),
        name="deprecated-user-scope",
    ),
    re_path(  # pragma: only django-ca<2.3.0
        r"^deprecated-attribute-scope/(?P<serial>[0-9A-F:]+)/$",
        CertificateRevocationListView.as_view(scope="attribute"),
        name="deprecated-attribute-scope",
    ),
]


@pytest.fixture
def default_url(root: CertificateAuthority) -> str:
    """Fixture for the default URL for the root CA."""
    return reverse("default", kwargs={"serial": root.serial})


@pytest.fixture
def deprecated_scope() -> Iterator[None]:
    """Warning for deprecated scope parameter."""
    msg = (
        "The scope parameter is deprecated and will be removed in django-ca 2.3.0, use "
        "`only_contains_{ca,user,attribute}_cert` instead."
    )
    with assert_removed_in_230(msg):
        yield


def test_full_crl(
    django_assert_num_queries: DjangoAssertNumQueries,
    client: Client,
    default_url: str,
    root_crl: CertificateRevocationList,
) -> None:
    """Fetch a full CRL (= CA and user certs, all reasons)."""
    with django_assert_num_queries(0):
        response = client.get(default_url)
    assert response.status_code == HTTPStatus.OK
    assert response["Content-Type"] == "application/pkix-crl"
    assert response.content == root_crl.data


def test_ca_crl(
    django_assert_num_queries: DjangoAssertNumQueries, client: Client, root_ca_crl: CertificateRevocationList
) -> None:
    """Fetch a CA CRL."""
    with django_assert_num_queries(0):
        response = client.get(reverse("ca", kwargs={"serial": root_ca_crl.ca.serial}))
    assert response.status_code == HTTPStatus.OK
    assert response["Content-Type"] == "application/pkix-crl"
    assert response.content == root_ca_crl.data


def test_user_crl(client: Client, root_user_crl: CertificateRevocationList) -> None:
    """Fetch a user CRL."""
    response = client.get(reverse("user", kwargs={"serial": root_user_crl.ca.serial}))
    assert response.status_code == HTTPStatus.OK
    assert response["Content-Type"] == "application/pkix-crl"
    assert response.content == root_user_crl.data


def test_with_cache_miss(
    django_assert_num_queries: DjangoAssertNumQueries,
    client: Client,
    default_url: str,
    root_crl: CertificateRevocationList,
) -> None:
    """Fetch a full CRL with a cache miss."""
    cache.clear()  # clear the cache to generate a cache miss

    with django_assert_num_queries(1) as captured:  # Only one query for fetching the CRL required
        response = client.get(default_url)
    assert 'FROM "django_ca_certificaterevocationlist" INNER JOIN' in captured.captured_queries[0]["sql"]

    assert response.status_code == HTTPStatus.OK
    assert response["Content-Type"] == "application/pkix-crl"
    assert response.content == root_crl.data


def test_regenerate_full_crl(
    django_assert_num_queries: DjangoAssertNumQueries,
    client: Client,
    usable_root: CertificateAuthority,
    default_url: str,
) -> None:
    """Fetch a full CRL where the CRL has to be regenerated."""
    with django_assert_num_queries(9):  # loads of queries required to regenerate a CRL
        response = client.get(default_url)

    assert response.status_code == HTTPStatus.OK
    assert response["Content-Type"] == "application/pkix-crl"
    assert_crl(response.content, expected=[], encoding=Encoding.DER, signer=usable_root)


def test_regenerate_ca_crl(client: Client, usable_root: CertificateAuthority) -> None:
    """Fetch a full CRL where the CRL has to be regenerated."""
    response = client.get(reverse("ca", kwargs={"serial": usable_root.serial}))
    assert response.status_code == HTTPStatus.OK
    assert response["Content-Type"] == "application/pkix-crl"
    idp = get_idp(only_contains_ca_certs=True)
    assert_crl(response.content, expected=[], encoding=Encoding.DER, signer=usable_root, idp=idp)


def test_regenerate_user_crl(client: Client, usable_root: CertificateAuthority) -> None:
    """Fetch a full CRL where the CRL has to be regenerated."""
    response = client.get(reverse("user", kwargs={"serial": usable_root.serial}))
    assert response.status_code == HTTPStatus.OK
    assert response["Content-Type"] == "application/pkix-crl"
    idp = get_idp(only_contains_user_certs=True)
    assert_crl(response.content, expected=[], encoding=Encoding.DER, signer=usable_root, idp=idp)


def test_regenerate_full_crl_with_reasons(
    client: Client, usable_root: CertificateAuthority, root_cert: Certificate
) -> None:
    """Fetch a CRL with only some reasons where the CRL has to be regenerated."""
    root_cert.revoke(constants.ReasonFlags.key_compromise)
    response = client.get(reverse("reasons", kwargs={"serial": usable_root.serial}))
    assert response.status_code == HTTPStatus.OK
    assert response["Content-Type"] == "application/pkix-crl"
    idp = get_idp(only_some_reasons=frozenset([x509.ReasonFlags.key_compromise]))
    assert_crl(
        response.content,
        expected=[root_cert],
        encoding=Encoding.DER,
        signer=usable_root,
        idp=idp,
        entry_extensions=(
            (
                [
                    x509.Extension(
                        oid=x509.CRLReason.oid,
                        critical=False,
                        value=x509.CRLReason(x509.ReasonFlags.key_compromise),
                    )
                ],
            )
        ),
    )


def test_regenerate_full_crl_with_reasons_without_matching_certs(
    client: Client, usable_root: CertificateAuthority, root_cert: Certificate
) -> None:
    """Fetch a CRL with only some reasons where the CRL has to be regenerated, but no cert matches."""
    root_cert.revoke(constants.ReasonFlags.aa_compromise)
    response = client.get(reverse("reasons", kwargs={"serial": usable_root.serial}))
    assert response.status_code == HTTPStatus.OK
    assert response["Content-Type"] == "application/pkix-crl"
    idp = get_idp(only_some_reasons=frozenset([x509.ReasonFlags.key_compromise]))
    assert_crl(response.content, expected=[], encoding=Encoding.DER, signer=usable_root, idp=idp)


def test_with_object_not_in_database(
    client: Client, default_url: str, root_crl: CertificateRevocationList
) -> None:
    """Fetch a full CRL where the CRL is in the cache, but not in the database (should not happen)."""
    root_crl.delete()  # delete the object - view still works b/c of cache
    response = client.get(default_url)
    assert response.status_code == HTTPStatus.OK
    assert response["Content-Type"] == "application/pkix-crl"
    assert response.content == root_crl.data


def test_force_encoding(client: Client, default_url: str, root_crl: CertificateRevocationList) -> None:
    """Test that forcing a different encoding."""
    response = client.get(default_url, data={"encoding": "PEM"})
    assert response.status_code == HTTPStatus.OK
    assert response["Content-Type"] == "text/plain", response.content
    assert response.content == root_crl.pem


def test_force_encoding_with_cache_miss(
    client: Client, default_url: str, root_crl: CertificateRevocationList
) -> None:
    """Test that forcing a different encoding."""
    cache.clear()
    response = client.get(default_url, data={"encoding": "PEM"})
    assert response.status_code == HTTPStatus.OK
    assert response["Content-Type"] == "text/plain"
    assert response.content == root_crl.pem


def test_view_configuration(client: Client, usable_root: CertificateAuthority) -> None:
    """Test fetching the CRL for a manually configured view that overrides some settings."""
    response = client.get(reverse("advanced", kwargs={"serial": usable_root.serial}))
    assert response.status_code == HTTPStatus.OK
    assert response["Content-Type"] == "foo/bar"
    assert_crl(response.content, expires=321, algorithm=hashes.SHA256(), signer=usable_root)


@pytest.mark.usefixtures("deprecated_scope")
def test_deprecated_full_scope(client: Client, root_crl: CertificateRevocationList) -> None:
    """Test fetching deprecated `scope` parameter with value `None`."""
    response = client.get(reverse("deprecated-full-scope", kwargs={"serial": ROOT_SERIAL}))
    assert response.status_code == HTTPStatus.OK
    assert response.content == root_crl.data


@pytest.mark.usefixtures("deprecated_scope")
def test_deprecated_ca_scope(client: Client, root_ca_crl: CertificateRevocationList) -> None:
    """Test fetching deprecated `scope` parameter with value `ca`."""
    response = client.get(reverse("deprecated-ca-scope", kwargs={"serial": ROOT_SERIAL}))
    assert response.status_code == HTTPStatus.OK
    assert response.content == root_ca_crl.data


@pytest.mark.usefixtures("deprecated_scope")
def test_deprecated_user_scope(client: Client, root_user_crl: CertificateRevocationList) -> None:
    """Test fetching deprecated `scope` parameter with value `user`."""
    response = client.get(reverse("deprecated-user-scope", kwargs={"serial": ROOT_SERIAL}))
    assert response.status_code == HTTPStatus.OK
    assert response.content == root_user_crl.data


@pytest.mark.django_db
@pytest.mark.usefixtures("deprecated_scope")
def test_deprecated_attribute_scope(client: Client, root_attribute_crl: CertificateRevocationList) -> None:
    """Test fetching deprecated `scope` parameter with value `user`."""
    response = client.get(reverse("deprecated-attribute-scope", kwargs={"serial": ROOT_SERIAL}))
    assert response.status_code == HTTPStatus.OK
    assert response.content == root_attribute_crl.data


@pytest.mark.django_db
def test_regenerate_with_unusable_ca(client: Client, default_url: str) -> None:
    """Fetch CRL when it has to be regenerated but the private key is not usable."""
    response = client.get(default_url)
    assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
    assert response["Content-Type"] == "text/plain"
    assert response.content == b"Error while retrieving the CRL."


def test_password_with_missing_password(
    client: Client, usable_pwd: CertificateAuthority, settings: SettingsWrapper
) -> None:
    """Try getting the CRL for an encrypted CA where there is no password (which fails)."""
    settings.CA_PASSWORDS = {}
    response = client.get(reverse("default", kwargs={"serial": usable_pwd.serial}))
    assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
    assert response["Content-Type"] == "text/plain"
    assert response.content == b"Error while retrieving the CRL."


def test_invalid_encoding(client: Client, default_url: str) -> None:
    """Test that forcing an unsupported encoding."""
    response = client.get(default_url, {"encoding": "X962"})
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response["Content-Type"] == "text/plain"
    assert response.content == b"X962: Invalid encoding requested."
