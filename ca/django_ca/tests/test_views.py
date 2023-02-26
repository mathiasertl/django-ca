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

"""Test basic views."""

import copy

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

from django.core.cache import cache
from django.test import TestCase
from django.test.utils import override_settings
from django.urls import include, path, re_path, reverse

from freezegun import freeze_time

from django_ca import ca_settings
from django_ca.tests.base import certs, override_tmpcadir, uri
from django_ca.tests.base.mixins import TestCaseMixin
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
            digest=hashes.SHA256(),
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


class GenericCRLViewTestsMixin(TestCaseMixin):
    """Mixin with test cases for CertificateRevocationListView.

    Why is this a separate mixin: https://github.com/spulec/freezegun/issues/485
    """

    load_cas = (
        "root",
        "child",
        "pwd",
    )
    load_certs = ("child-cert",)

    @override_tmpcadir()
    def test_basic(self) -> None:
        """Basic test."""
        # test the default view
        idp = self.get_idp(full_name=self.get_idp_full_name(self.ca), only_contains_user_certs=True)
        response = self.client.get(reverse("default", kwargs={"serial": self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pkix-crl")
        self.assertCRL(
            response.content,
            encoding=Encoding.DER,
            expires=600,
            idp=idp,
            algorithm=self.ca.algorithm,
        )

        # revoke a certificate
        self.cert.revoke()

        # fetch again - we should see a cached response
        response = self.client.get(reverse("default", kwargs={"serial": self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pkix-crl")
        self.assertCRL(
            response.content,
            encoding=Encoding.DER,
            expires=600,
            idp=idp,
            algorithm=self.ca.algorithm,
        )

        # clear the cache and fetch again
        cache.clear()
        response = self.client.get(reverse("default", kwargs={"serial": self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pkix-crl")
        self.assertCRL(
            response.content,
            expected=[self.cert],
            encoding=Encoding.DER,
            expires=600,
            idp=idp,
            crl_number=1,
            algorithm=self.ca.algorithm,
        )

    @override_tmpcadir()
    def test_full_scope(self) -> None:
        """Test getting CRL with full scope."""
        full_name = "http://localhost/crl"
        idp = self.get_idp(full_name=[uri(full_name)])

        self.ca.crl_url = full_name
        self.ca.save()

        response = self.client.get(reverse("full", kwargs={"serial": self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pkix-crl")
        self.assertCRL(
            response.content,
            encoding=Encoding.DER,
            expires=600,
            idp=idp,
            algorithm=self.ca.algorithm,
        )

        # If scope is None, CRLs for a root CA should *not* include the IssuingDistributionPoint extension:
        response = self.client.get(reverse("full", kwargs={"serial": self.cas["root"].serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pkix-crl")
        self.assertCRL(
            response.content,
            encoding=Encoding.DER,
            expires=600,
            signer=self.cas["root"],
            idp=None,
            algorithm=self.ca.algorithm,
        )

    @override_tmpcadir()
    def test_ca_crl(self) -> None:
        """Test getting a CA CRL."""
        root = self.cas["root"]
        child = self.cas["child"]
        idp = self.get_idp(only_contains_ca_certs=True)  # root CAs don't have a full name (github issue #64)
        self.assertIsNotNone(root.key(password=None))

        response = self.client.get(reverse("ca_crl", kwargs={"serial": root.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/plain")
        self.assertCRL(response.content, expires=600, idp=idp, signer=root, algorithm=root.algorithm)

        child.revoke()
        child.save()

        # fetch again - we should see a cached response
        response = self.client.get(reverse("ca_crl", kwargs={"serial": root.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/plain")
        self.assertCRL(response.content, expires=600, idp=idp, signer=root, algorithm=root.algorithm)

        # clear the cache and fetch again
        cache.clear()
        response = self.client.get(reverse("ca_crl", kwargs={"serial": root.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/plain")
        self.assertCRL(
            response.content,
            expected=[child],
            expires=600,
            idp=idp,
            crl_number=1,
            signer=root,
            algorithm=root.algorithm,
        )

    @override_tmpcadir()
    def test_ca_crl_intermediate(self) -> None:
        """Test getting CRL for an intermediate CA."""
        child = self.cas["child"]
        full_name = [uri(f"http://{ca_settings.CA_DEFAULT_HOSTNAME}/django_ca/crl/ca/{child.serial}/")]
        idp = self.get_idp(full_name=full_name, only_contains_ca_certs=True)
        self.assertIsNotNone(child.key(password=None))

        response = self.client.get(reverse("ca_crl", kwargs={"serial": child.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/plain")
        self.assertCRL(response.content, expires=600, idp=idp, signer=child, algorithm=child.algorithm)

    @override_tmpcadir()
    def test_password(self) -> None:
        """Test getting a CRL with a password."""
        ca = self.cas["pwd"]

        # getting CRL from view directly doesn't work
        with self.assertRaisesRegex(TypeError, r"^Password was not given but private key is encrypted$"):
            self.client.get(reverse("default", kwargs={"serial": ca.serial}))

        profiles = copy.deepcopy(ca_settings.CA_CRL_PROFILES)
        for config in profiles.values():
            config.setdefault("OVERRIDES", {})
            config["OVERRIDES"].setdefault(ca.serial, {})
            config["OVERRIDES"][ca.serial]["password"] = certs["pwd"]["password"]

        with override_settings(CA_CRL_PROFILES=profiles):
            ca.cache_crls()  # cache CRLs for this CA

        idp = self.get_idp(full_name=self.get_idp_full_name(ca), only_contains_user_certs=True)
        response = self.client.get(reverse("default", kwargs={"serial": ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pkix-crl")
        self.assertCRL(
            response.content,
            encoding=Encoding.DER,
            idp=idp,
            signer=ca,
            algorithm=ca.algorithm,
        )

    @override_tmpcadir()
    def test_overwrite(self) -> None:
        """Test overwriting a CRL."""
        idp = self.get_idp(full_name=self.get_idp_full_name(self.ca), only_contains_user_certs=True)
        response = self.client.get(reverse("advanced", kwargs={"serial": self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/plain")
        self.assertCRL(response.content, expires=321, idp=idp, algorithm=hashes.SHA256())

    @override_tmpcadir()
    def test_force_idp_inclusion(self) -> None:
        """Test that forcing inclusion of CRLs works."""
        # View still works with self.ca, because its the child CA
        idp = self.get_idp(full_name=self.get_idp_full_name(self.ca))
        response = self.client.get(reverse("include_idp", kwargs={"serial": self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pkix-crl")
        self.assertCRL(
            response.content, encoding=Encoding.DER, expires=600, idp=idp, algorithm=self.ca.algorithm
        )

        with self.assertRaisesRegex(
            ValueError,
            r"^Cannot add IssuingDistributionPoint extension to CRLs with no scope for root CAs\.$",
        ):
            response = self.client.get(reverse("include_idp", kwargs={"serial": self.cas["root"].serial}))

    @override_tmpcadir()
    def test_force_idp_exclusion(self) -> None:
        """Test that forcing exclusion of CRLs works."""
        response = self.client.get(reverse("exclude_idp", kwargs={"serial": self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pkix-crl")
        self.assertCRL(
            response.content, encoding=Encoding.DER, expires=600, idp=None, algorithm=self.ca.algorithm
        )


@override_settings(ROOT_URLCONF=__name__)
@freeze_time("2019-04-14 12:26:00")
class GenericCRLViewTests(GenericCRLViewTestsMixin, TestCase):
    """Test CertificateRevocationListView."""


@override_settings(ROOT_URLCONF=__name__, USE_TZ=True)
@freeze_time("2019-04-14 12:26:00")
class GenericCRLWithTZViewTests(GenericCRLViewTestsMixin, TestCase):
    """Test CertificateRevocationListView with timezone support."""


class GenericCAIssuersViewTests(TestCaseMixin, TestCase):
    """Test issuer view."""

    load_cas = "__usable__"

    def test_view(self) -> None:
        """Basic test for the view."""
        for ca in self.cas.values():
            url = reverse("django_ca:issuer", kwargs={"serial": ca.root.serial})
            resp = self.client.get(url)
            self.assertEqual(resp["Content-Type"], "application/pkix-cert")
            self.assertEqual(resp.content, ca.root.pub.der)
