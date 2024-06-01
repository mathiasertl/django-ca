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

from datetime import datetime, timedelta, timezone as tz
from http import HTTPStatus

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

from django.core.cache import cache
from django.test import Client
from django.urls import include, path, re_path, reverse

import pytest
from freezegun.api import FrozenDateTimeFactory
from pytest_django.fixtures import SettingsWrapper

from django_ca.conf import model_settings
from django_ca.models import Certificate, CertificateAuthority
from django_ca.tests.base.assertions import assert_crl
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS
from django_ca.tests.base.utils import get_idp, idp_full_name
from django_ca.views import CertificateRevocationListView

app_name = "django_ca"
urlpatterns = [
    path("django_ca/", include("django_ca.urls")),
    re_path(r"^crl/(?P<serial>[0-9A-F:]+)/$", CertificateRevocationListView.as_view(), name="default"),
    re_path(
        r"^full/(?P<serial>[0-9A-F:]+)/$", CertificateRevocationListView.as_view(scope=None), name="full"
    ),
    re_path(
        r"^adv/(?P<serial>[0-9A-F:]+)/$",
        CertificateRevocationListView.as_view(
            content_type="text/plain",
            expires=321,
            type=Encoding.PEM,
        ),
        name="advanced",
    ),
    re_path(
        r"^crl/ca/(?P<serial>[0-9A-F:]+)/$",
        CertificateRevocationListView.as_view(scope="ca", type=Encoding.PEM),
        name="ca_crl",
    ),
    re_path(
        r"^include_idp/(?P<serial>[0-9A-F:]+)/$",
        CertificateRevocationListView.as_view(scope=None, include_issuing_distribution_point=True),
        name="include_idp",
    ),
    re_path(
        r"^exclude_idp/(?P<serial>[0-9A-F:]+)/$",
        CertificateRevocationListView.as_view(scope=None, include_issuing_distribution_point=False),
        name="exclude_idp",
    ),
]


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
@pytest.mark.usefixtures("clear_cache")
@pytest.mark.urls(__name__)
class TestCertificateRevocationListView:
    """Mixin with test cases for CertificateRevocationListView.

    Why is this a separate mixin: https://github.com/spulec/freezegun/issues/485
    """

    def test_basic_response(
        self,
        client: Client,
        freezer: FrozenDateTimeFactory,
        usable_child: CertificateAuthority,
        child_cert: Certificate,
    ) -> None:
        """Basic test."""
        # test the default view
        url = reverse("default", kwargs={"serial": usable_child.serial})
        idp = get_idp(full_name=idp_full_name(usable_child), only_contains_user_certs=True)
        response = client.get(url)
        assert response.status_code == HTTPStatus.OK
        assert response["Content-Type"] == "application/pkix-crl"
        assert_crl(
            response.content, expected=[], encoding=Encoding.DER, signer=usable_child, expires=600, idp=idp
        )

        # revoke a certificate
        child_cert.revoke()

        # Advance time so that we see that the cached CRL now expires sooner.
        last_update = datetime.now(tz=tz.utc)
        freezer.tick(timedelta(seconds=10))

        # fetch again - we should see a cached response
        response = client.get(url)
        assert response.status_code == HTTPStatus.OK
        assert response["Content-Type"] == "application/pkix-crl"
        assert_crl(
            response.content,
            expected=[],  # still an empty response, because it was cached
            encoding=Encoding.DER,
            signer=usable_child,
            expires=590,  # time advanced by ten seconds above
            idp=idp,
            last_update=last_update,
        )

        # clear the cache and fetch again
        cache.clear()
        response = client.get(url)
        assert response.status_code == HTTPStatus.OK
        assert response["Content-Type"] == "application/pkix-crl"
        assert_crl(
            response.content,
            expected=[child_cert],  # now includes certificate
            encoding=Encoding.DER,
            signer=usable_child,
            expires=600,  # again 600
            idp=idp,
            crl_number=1,  # regenerated
        )

    def test_full_scope_with_child_ca(self, client: Client, usable_child: CertificateAuthority) -> None:
        """Test getting CRL with full scope."""
        full_name = usable_child.sign_crl_distribution_points.value[0].full_name  # type: ignore[union-attr]
        idp = get_idp(full_name=full_name)

        response = client.get(reverse("full", kwargs={"serial": usable_child.serial}))
        assert response.status_code == HTTPStatus.OK
        assert response["Content-Type"] == "application/pkix-crl"
        assert_crl(response.content, expected=[], encoding=Encoding.DER, expires=600, idp=idp)

    def test_full_scope_with_root_ca(
        self,
        client: Client,
        usable_root: CertificateAuthority,
        child: CertificateAuthority,
        root_cert: Certificate,
    ) -> None:
        """Test getting CRL with full scope and a revoked CA and cert."""
        assert child.parent == usable_root  # test assumption
        assert root_cert.ca == usable_root  # test assumption

        response = client.get(reverse("full", kwargs={"serial": usable_root.serial}))
        assert response.status_code == HTTPStatus.OK
        assert response["Content-Type"] == "application/pkix-crl"
        assert_crl(
            response.content, expected=[], encoding=Encoding.DER, expires=600, signer=usable_root, idp=None
        )

    def test_full_scope_with_root_ca_with_revoked_entities(
        self,
        client: Client,
        usable_root: CertificateAuthority,
        child: CertificateAuthority,
        root_cert: Certificate,
    ) -> None:
        """Test getting CRL with full scope and a revoked CA and cert."""
        assert child.parent == usable_root  # test assumption
        assert root_cert.ca == usable_root  # test assumption
        child.revoke()
        root_cert.revoke()

        response = client.get(reverse("full", kwargs={"serial": usable_root.serial}))
        assert response.status_code == HTTPStatus.OK
        assert response["Content-Type"] == "application/pkix-crl"
        # full scope includes both CAs and certs:
        assert_crl(
            response.content,
            expected=[child, root_cert],
            encoding=Encoding.DER,
            expires=600,
            signer=usable_root,
            idp=None,
        )

    def test_ca_crl(
        self, client: Client, usable_root: CertificateAuthority, child: CertificateAuthority
    ) -> None:
        """Test getting a CA CRL."""
        idp = get_idp(only_contains_ca_certs=True)  # root CAs don't have a full name (GitHub issue #64)
        child.revoke()

        response = client.get(reverse("ca_crl", kwargs={"serial": usable_root.serial}))
        assert response.status_code == HTTPStatus.OK
        assert response["Content-Type"] == "text/plain"
        assert_crl(response.content, expected=[child], expires=600, idp=idp, signer=usable_root)

    def test_password(self, client: Client, usable_pwd: CertificateAuthority) -> None:
        """Test getting a CRL for a CA that is encrypted with a password."""
        # Make sure that the password is actually set
        assert model_settings.CA_PASSWORDS[usable_pwd.serial] == CERT_DATA["pwd"]["password"]

        idp = get_idp(full_name=idp_full_name(usable_pwd), only_contains_user_certs=True)
        response = client.get(reverse("default", kwargs={"serial": usable_pwd.serial}))
        assert response.status_code == HTTPStatus.OK
        assert response["Content-Type"] == "application/pkix-crl"
        assert_crl(response.content, encoding=Encoding.DER, expires=600, idp=idp, signer=usable_pwd)

    def test_password_with_missing_password(
        self, client: Client, usable_pwd: CertificateAuthority, settings: SettingsWrapper
    ) -> None:
        """Try getting the CRL for an encrypted CA where there is no password (which fails)."""
        settings.CA_PASSWORDS = {}
        response = client.get(reverse("default", kwargs={"serial": usable_pwd.serial}))
        assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
        assert response["Content-Type"] == "text/plain"
        assert response.content == b"Error while retrieving the CRL."

    def test_password_with_cached_response(
        self, client: Client, usable_pwd: CertificateAuthority, settings: SettingsWrapper
    ) -> None:
        """Test getting the CRL for an encrypted CA where the response was cached (by cache_crls())."""
        # Cache CRLs (NOTE: password is fetched from CA_PASSWORDS during model validation)
        key_backend_options = usable_pwd.key_backend.get_use_private_key_options(usable_pwd, {})
        usable_pwd.cache_crls(key_backend_options)  # cache CRLs for this CA

        # Clear password in settings, so this will now only work if we find the CRL in the cache.
        settings.CA_PASSWORDS = {}

        idp = get_idp(full_name=idp_full_name(usable_pwd), only_contains_user_certs=True)
        response = client.get(reverse("default", kwargs={"serial": usable_pwd.serial}))
        assert response.status_code == HTTPStatus.OK
        assert response["Content-Type"] == "application/pkix-crl"
        assert_crl(response.content, encoding=Encoding.DER, idp=idp, signer=usable_pwd)

    def test_view_configuration(self, client: Client, usable_child: CertificateAuthority) -> None:
        """Test fetching the CRL for a manually configured view that overrides some settings."""
        idp = get_idp(full_name=idp_full_name(usable_child), only_contains_user_certs=True)
        response = client.get(reverse("advanced", kwargs={"serial": usable_child.serial}))
        assert response.status_code == HTTPStatus.OK
        assert response["Content-Type"] == "text/plain"
        assert_crl(response.content, expires=321, idp=idp, algorithm=hashes.SHA256())

    def test_force_idp_inclusion(self, client: Client, usable_child: CertificateAuthority) -> None:
        """Test that forcing inclusion of CRLs works."""
        # View still works with self.ca, because it's the child CA
        idp = get_idp(full_name=idp_full_name(usable_child))
        response = client.get(reverse("include_idp", kwargs={"serial": usable_child.serial}))
        assert response.status_code == HTTPStatus.OK
        assert response["Content-Type"] == "application/pkix-crl"
        assert_crl(response.content, encoding=Encoding.DER, expires=600, idp=idp)

    def test_force_idp_inclusion_with_root(self, client: Client, usable_root: CertificateAuthority) -> None:
        """Test forcing an IDP for a root CA (which fails, because it cannot have an IDP)."""
        response = client.get(reverse("include_idp", kwargs={"serial": usable_root.serial}))
        assert response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR
        assert response["Content-Type"] == "text/plain"
        assert response.content == b"Error while retrieving the CRL."

    def test_force_idp_exclusion(self, client: Client, usable_child: CertificateAuthority) -> None:
        """Test that forcing exclusion of CRLs works."""
        response = client.get(reverse("exclude_idp", kwargs={"serial": usable_child.serial}))
        assert response.status_code == HTTPStatus.OK
        assert response["Content-Type"] == "application/pkix-crl"
        assert_crl(response.content, encoding=Encoding.DER, expires=600, idp=None)

    def test_force_encoding(self, client: Client, usable_root: CertificateAuthority) -> None:
        """Test that forcing a different encoding."""
        idp = get_idp(full_name=idp_full_name(usable_root), only_contains_user_certs=True)
        response = client.get(reverse("default", kwargs={"serial": usable_root.serial}), {"encoding": "PEM"})
        assert response.status_code == HTTPStatus.OK
        assert response["Content-Type"] == "text/plain"
        assert_crl(response.content, signer=usable_root, encoding=Encoding.PEM, expires=600, idp=idp)

    def test_invalid_encoding(self, client: Client, usable_root: CertificateAuthority) -> None:
        """Test that forcing an unsupported encoding."""
        response = client.get(reverse("default", kwargs={"serial": usable_root.serial}), {"encoding": "X962"})
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response["Content-Type"] == "text/plain"
        assert response.content == b"X962: Invalid encoding requested."


def test_generic_ca_issuers_view(usable_root: CertificateAuthority, client: Client) -> None:
    """Test the generic ca issuer view."""
    url = reverse("django_ca:issuer", kwargs={"serial": usable_root.serial})
    resp = client.get(url)
    assert resp["Content-Type"] == "application/pkix-cert"
    assert resp.content == usable_root.pub.der
