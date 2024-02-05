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

"""Test extra admin vies."""

import json
import typing
from http import HTTPStatus
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from django.contrib.auth.models import Permission
from django.test import Client, TestCase
from django.urls import reverse

import pytest

from django_ca import constants
from django_ca.models import CertificateAuthority
from django_ca.tests.admin.base import CertificateModelAdminTestCaseMixin
from django_ca.tests.base.constants import CERT_DATA
from django_ca.typehints import JSON


@pytest.mark.parametrize(
    "data,expected",
    (
        ([], ""),
        ([{"oid": NameOID.COMMON_NAME.dotted_string, "value": "example.com"}], "CN=example.com"),
        (
            [
                {"oid": NameOID.COUNTRY_NAME.dotted_string, "value": "AT"},
                {"oid": NameOID.ORGANIZATION_NAME.dotted_string, "value": "MyOrg"},
                {"oid": NameOID.COMMON_NAME.dotted_string, "value": "example.com"},
            ],
            "C=AT,O=MyOrg,CN=example.com",
        ),
    ),
)
def test_name_to_rfc4514_view(admin_client: Client, data: JSON, expected: str) -> None:
    """Test admin API for converting names to RFC 4514 strings."""
    url = reverse("admin:django_ca_certificate_name_to_rfc4514")
    response = admin_client.post(url, data=json.dumps(data), content_type="application/json")
    assert response.status_code == HTTPStatus.OK
    assert response.json() == {"name": expected}


def test_unauthenticated(client: Client, extra_view_url: str) -> None:
    """Test that extra views cannot be accessed by an unauthenticated user."""
    response = client.get(extra_view_url)
    assert response.status_code == HTTPStatus.FOUND
    assert response["Location"] == f"/admin/login/?next={extra_view_url}"


def test_no_permissions(user_client: Client, extra_view_url: str) -> None:
    """Test that extra views cannot be accessed by a user that is not a staff user."""
    response = user_client.get(extra_view_url)
    assert response.status_code == HTTPStatus.FOUND
    assert response["Location"] == f"/admin/login/?next={extra_view_url}"


def test_staff_user_with_no_permissions(staff_client: Client, extra_view_url: str) -> None:
    """Test that extra views cannot be accessed by a staff user that does not have any permissions."""
    response = staff_client.get(extra_view_url)
    assert response.status_code == HTTPStatus.FORBIDDEN


class CSRDetailTestCase(CertificateModelAdminTestCaseMixin, TestCase):
    """Test the CSR detail view."""

    url = reverse("admin:django_ca_certificate_csr_details")
    csr_pem = CERT_DATA["root-cert"]["csr"]["pem"]

    @classmethod
    def create_csr(
        cls, subject: x509.Name
    ) -> Tuple[CertificateIssuerPrivateKeyTypes, x509.CertificateSigningRequest]:
        """Generate a CSR with the given subject."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        builder = x509.CertificateSigningRequestBuilder()

        builder = builder.subject_name(subject)
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        request = builder.sign(private_key, hashes.SHA256())

        return private_key, request

    def test_basic(self) -> None:
        """Test a basic CSR info retrieval."""
        for cert_data in [v for v in CERT_DATA.values() if v["type"] == "cert" and v["cat"] == "generated"]:
            response = self.client.post(
                self.url, data=json.dumps({"csr": cert_data["csr"]["pem"]}), content_type="application/json"
            )
            self.assertEqual(response.status_code, 200, response.json())
            csr_subject = cert_data["csr"]["parsed"].subject
            self.assertEqual(
                response.json(),
                {"subject": [{"oid": s.oid.dotted_string, "value": s.value} for s in csr_subject]},
            )

    def test_fields(self) -> None:
        """Test fetching a CSR with all subject fields."""
        subject = [
            x509.NameAttribute(
                oid=oid, value="AT" if name in ("countryName", "jurisdictionCountryName") else f"test-{name}"
            )
            for oid, name in constants.NAME_OID_NAMES.items()
            if oid != NameOID.X500_UNIQUE_IDENTIFIER
        ]
        csr = self.create_csr(x509.Name(sorted(subject, key=lambda attr: attr.oid.dotted_string)))[1]
        csr_pem = csr.public_bytes(Encoding.PEM).decode("utf-8")

        response = self.client.post(
            self.url, data=json.dumps({"csr": csr_pem}), content_type="application/json"
        )
        self.assertEqual(response.status_code, 200, response.json())
        expected = [
            {"oid": NameOID.USER_ID.dotted_string, "value": "test-uid"},
            {"oid": NameOID.DOMAIN_COMPONENT.dotted_string, "value": "test-domainComponent"},
            {"oid": NameOID.OGRN.dotted_string, "value": "test-ogrn"},
            {"oid": NameOID.SNILS.dotted_string, "value": "test-snils"},
            {"oid": NameOID.INN.dotted_string, "value": "test-inn"},
            {"oid": NameOID.EMAIL_ADDRESS.dotted_string, "value": "test-emailAddress"},
            {"oid": NameOID.UNSTRUCTURED_NAME.dotted_string, "value": "test-unstructuredName"},
            {
                "oid": NameOID.JURISDICTION_LOCALITY_NAME.dotted_string,
                "value": "test-jurisdictionLocalityName",
            },
            {
                "oid": NameOID.JURISDICTION_STATE_OR_PROVINCE_NAME.dotted_string,
                "value": "test-jurisdictionStateOrProvinceName",
            },
            {"oid": NameOID.JURISDICTION_COUNTRY_NAME.dotted_string, "value": "AT"},
            {"oid": NameOID.ORGANIZATION_NAME.dotted_string, "value": "test-organizationName"},
            {"oid": NameOID.ORGANIZATIONAL_UNIT_NAME.dotted_string, "value": "test-organizationalUnitName"},
            {"oid": NameOID.TITLE.dotted_string, "value": "test-title"},
            {"oid": NameOID.BUSINESS_CATEGORY.dotted_string, "value": "test-businessCategory"},
            {"oid": NameOID.POSTAL_ADDRESS.dotted_string, "value": "test-postalAddress"},
            {"oid": NameOID.POSTAL_CODE.dotted_string, "value": "test-postalCode"},
            {"oid": NameOID.COMMON_NAME.dotted_string, "value": "test-commonName"},
            {"oid": NameOID.SURNAME.dotted_string, "value": "test-surname"},
            {"oid": NameOID.GIVEN_NAME.dotted_string, "value": "test-givenName"},
            {"oid": NameOID.INITIALS.dotted_string, "value": "test-initials"},
            {"oid": NameOID.GENERATION_QUALIFIER.dotted_string, "value": "test-generationQualifier"},
            {"oid": NameOID.DN_QUALIFIER.dotted_string, "value": "test-dnQualifier"},
            {"oid": NameOID.SERIAL_NUMBER.dotted_string, "value": "test-serialNumber"},
            # tmp
            {"oid": NameOID.COUNTRY_NAME.dotted_string, "value": "AT"},
            {"oid": NameOID.PSEUDONYM.dotted_string, "value": "test-pseudonym"},
            {"oid": NameOID.LOCALITY_NAME.dotted_string, "value": "test-localityName"},
            {"oid": NameOID.STATE_OR_PROVINCE_NAME.dotted_string, "value": "test-stateOrProvinceName"},
            {"oid": NameOID.STREET_ADDRESS.dotted_string, "value": "test-street"},
            # pragma: only cg<42: Replace "2.5.4.97" with NameOID.ORGANIZATION_IDENTIIFER
            {"oid": "2.5.4.97", "value": "test-organizationIdentifier"},
        ]

        self.assertEqual(json.loads(response.content.decode("utf-8")), {"subject": expected})

    def test_bad_request(self) -> None:
        """Test posting bogus data."""
        response = self.client.post(self.url, data={"csr": "foobar"})
        self.assertEqual(response.status_code, 400)

    def test_anonymous(self) -> None:
        """Try downloading as anonymous user."""
        client = Client()
        self.assertRequiresLogin(client.post(self.url, data={"csr": self.csr_pem}))

    def test_plain_user(self) -> None:
        """Try downloading as non-superuser."""
        self.user.is_superuser = self.user.is_staff = False
        self.user.save()
        self.assertRequiresLogin(self.client.post(self.url, data={"csr": self.csr_pem}))

    def test_no_perms(self) -> None:
        """Try downloading as staff user with missing permissions."""
        self.user.is_superuser = False
        self.user.save()
        response = self.client.post(self.url, data={"csr": self.csr_pem})
        self.assertEqual(response.status_code, 403)

    def test_no_staff(self) -> None:
        """Try downloading as user that has permissions but is not staff."""
        self.user.is_superuser = self.user.is_staff = False
        self.user.save()
        self.user.user_permissions.add(Permission.objects.get(codename="change_certificate"))
        self.assertRequiresLogin(self.client.post(self.url, data={"csr": self.csr_pem}))


class CertDownloadTestCase(CertificateModelAdminTestCaseMixin, TestCase):
    """Test fetching certificate bundles."""

    load_cas = ("root",)
    load_certs = ("root-cert",)
    view_name = "django_ca_certificate_download"

    def test_basic(self) -> None:
        """Test direct certificate download."""
        self.assertBundle(self.cert, [self.cert], "root-cert_example_com.pem")

    def test_der(self) -> None:
        """Download a certificate in DER format."""
        filename = "root-cert_example_com.der"
        response = self.client.get(self.get_url(self.cert), {"format": "DER"})
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(response["Content-Type"], "application/pkix-cert")
        self.assertEqual(response["Content-Disposition"], f"attachment; filename={filename}")
        self.assertEqual(response.content, self.cert.pub.der)

    def test_not_found(self) -> None:
        """Try downloading a certificate that does not exist."""
        url = reverse("admin:django_ca_certificate_download", kwargs={"pk": "123"})
        response = self.client.get(f"{url}?format=DER")
        self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND)

    def test_bad_format(self) -> None:
        """Try downloading an unknown format."""
        response = self.client.get(self.get_url(self.cert), {"format": "bad"})
        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
        self.assertEqual(response.content, b"")

    def test_anonymous(self) -> None:
        """Try an anonymous download."""
        self.assertRequiresLogin(Client().get(self.get_url(self.cert)))

    def test_plain_user(self) -> None:
        """Try downloading as plain user."""
        self.user.is_superuser = self.user.is_staff = False
        self.user.save()
        self.assertRequiresLogin(self.client.get(self.get_url(self.cert)))

    def test_no_perms(self) -> None:
        """Try downloading as staff user with no permissions."""
        self.user.is_superuser = False
        self.user.save()
        response = self.client.get(self.get_url(self.cert))
        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)

    def test_no_staff(self) -> None:
        """Try downloading with right permissions but not as staff user."""
        self.user.is_staff = False
        self.user.save()
        self.user.user_permissions.add(Permission.objects.get(codename="change_certificate"))
        self.assertRequiresLogin(self.client.get(self.get_url(self.cert)))


class CertDownloadBundleTestCase(CertificateModelAdminTestCaseMixin, TestCase):
    """Test downloading certificate bundles."""

    load_cas = (
        "root",
        "child",
    )
    load_certs = ("root-cert", "child-cert")
    view_name = "django_ca_certificate_download_bundle"

    def test_root_cert(self) -> None:
        """Try downloading a certificate bundle."""
        cert = self.certs["root-cert"]
        self.assertBundle(cert, [cert, cert.ca], "root-cert_example_com_bundle.pem")

    def test_child_cert(self) -> None:
        """Download bundle for certificate signed by intermediate ca."""
        parent = typing.cast(CertificateAuthority, self.cert.ca.parent)
        self.assertBundle(self.cert, [self.cert, self.cert.ca, parent], "child-cert_example_com_bundle.pem")

    def test_invalid_format(self) -> None:
        """Try downloading an invalid format."""
        url = self.get_url(self.cert)
        response = self.client.get(f"{url}?format=INVALID")
        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
        self.assertEqual(response.content, b"")

        # DER is not supported for bundles
        response = self.client.get(f"{url}?format=DER")
        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
        self.assertEqual(response.content, b"DER/ASN.1 certificates cannot be downloaded as a bundle.")
