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

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

from django.core.cache import cache
from django.test import Client
from django.urls import include
from django.urls import path
from django.urls import re_path
from django.urls import reverse

from freezegun import freeze_time

from .. import ca_settings
from ..views import CertificateRevocationListView
from .base import DjangoCAWithCertTestCase
from .base import DjangoCAWithGeneratedCAsTestCase
from .base import certs
from .base import override_settings
from .base import override_tmpcadir

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
            digest=hashes.MD5(),
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
]


# CRL code complains about 512 bit keys
@override_settings(ROOT_URLCONF=__name__, CA_MIN_KEY_SIZE=1024)
@freeze_time("2019-04-14 12:26:00")
class GenericCRLViewTests(DjangoCAWithCertTestCase):
    """Test generic CRL view."""

    def setUp(self):
        super().setUp()
        self.ca = self.cas["child"]
        self.client = Client()

    @override_tmpcadir()
    def test_basic(self):
        """Basic test."""
        # test the default view
        idp = self.get_idp(full_name=self.get_idp_full_name(self.ca), only_contains_user_certs=True)
        response = self.client.get(reverse("default", kwargs={"serial": self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pkix-crl")
        self.assertCRL(response.content, encoding=Encoding.DER, expires=600, idp=idp)

        # revoke a certificate
        cert = self.certs["child-cert"]
        cert.revoke()

        # fetch again - we should see a cached response
        response = self.client.get(reverse("default", kwargs={"serial": self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pkix-crl")
        self.assertCRL(response.content, encoding=Encoding.DER, expires=600, idp=idp)

        # clear the cache and fetch again
        cache.clear()
        response = self.client.get(reverse("default", kwargs={"serial": self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pkix-crl")
        self.assertCRL(
            response.content, expected=[cert], encoding=Encoding.DER, expires=600, idp=idp, crl_number=1
        )

    @override_tmpcadir()
    def test_full_scope(self):
        """Test getting CRL with full scope."""
        full_name = "http://localhost/crl"
        idp = self.get_idp(full_name=[x509.UniformResourceIdentifier(value=full_name)])

        self.ca.crl_url = full_name
        self.ca.save()

        response = self.client.get(reverse("full", kwargs={"serial": self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pkix-crl")
        self.assertCRL(response.content, encoding=Encoding.DER, expires=600, idp=idp)

    @override_tmpcadir()
    def test_ca_crl(self):
        """Test getting a CA CRL."""
        root = self.cas["root"]
        child = self.cas["child"]
        idp = self.get_idp(only_contains_ca_certs=True)  # root CAs don't have a full name (github issue #64)
        self.assertIsNotNone(root.key(password=None))

        response = self.client.get(reverse("ca_crl", kwargs={"serial": root.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/plain")
        self.assertCRL(response.content, expires=600, idp=idp, signer=root)

        child.revoke()
        child.save()

        # fetch again - we should see a cached response
        response = self.client.get(reverse("ca_crl", kwargs={"serial": root.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/plain")
        self.assertCRL(response.content, expires=600, idp=idp, signer=root)

        # clear the cache and fetch again
        cache.clear()
        response = self.client.get(reverse("ca_crl", kwargs={"serial": root.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/plain")
        self.assertCRL(response.content, expected=[child], expires=600, idp=idp, crl_number=1, signer=root)

    @override_tmpcadir()
    def test_ca_crl_intermediate(self):
        """Test getting CRL for an intermediate CA."""
        child = self.cas["child"]
        full_name = "http://%s/django_ca/crl/ca/%s/" % (ca_settings.CA_DEFAULT_HOSTNAME, child.serial)
        full_name = [x509.UniformResourceIdentifier(full_name)]
        idp = self.get_idp(full_name=full_name, only_contains_ca_certs=True)
        self.assertIsNotNone(child.key(password=None))

        response = self.client.get(reverse("ca_crl", kwargs={"serial": child.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/plain")
        self.assertCRL(response.content, expires=600, idp=idp, signer=child)

    @override_tmpcadir()
    def test_password(self):
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
        self.assertCRL(response.content, encoding=Encoding.DER, idp=idp, signer=ca)

    @override_tmpcadir()
    def test_overwrite(self):
        """Test overwriting a CRL."""
        idp = self.get_idp(full_name=self.get_idp_full_name(self.ca), only_contains_user_certs=True)
        response = self.client.get(reverse("advanced", kwargs={"serial": self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/plain")
        self.assertCRL(response.content, expires=321, idp=idp, algorithm=hashes.MD5())


@override_settings(USE_TZ=True)
class GenericCRLWithTZViewTests(GenericCRLViewTests):
    """Same but with timezone support."""


class GenericCAIssuersViewTests(DjangoCAWithGeneratedCAsTestCase):
    """Test issuer view."""

    def test_view(self):
        """Basic test for the view."""
        client = Client()

        for ca in self.cas.values():
            url = reverse("django_ca:issuer", kwargs={"serial": ca.root.serial})
            resp = client.get(url)
            self.assertEqual(resp["Content-Type"], "application/pkix-cert")
            self.assertEqual(resp.content, ca.root.x509_cert.public_bytes(encoding=Encoding.DER))
