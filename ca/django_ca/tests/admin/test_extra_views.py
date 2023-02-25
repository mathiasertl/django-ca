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
# <http://www.gnu.org/licenses/>

"""Test extra admin vies."""

import json
import typing
from http import HTTPStatus

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding

from django.contrib.auth.models import Permission
from django.test import Client, TestCase
from django.urls import reverse

from freezegun import freeze_time

from django_ca import ca_settings, constants
from django_ca.models import CertificateAuthority
from django_ca.tests.admin.base import CertificateModelAdminTestCaseMixin
from django_ca.tests.base import certs, override_tmpcadir, timestamps
from django_ca.typehints import PrivateKeyTypes
from django_ca.utils import x509_name


class CSRDetailTestCase(CertificateModelAdminTestCaseMixin, TestCase):
    """Test the CSR detail view."""

    url = reverse("admin:django_ca_certificate_csr_details")
    csr_pem = certs["root-cert"]["csr"]["pem"]

    @classmethod
    def create_csr(cls, subject: str) -> typing.Tuple[PrivateKeyTypes, x509.CertificateSigningRequest]:
        """Generate a CSR with the given subject."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        builder = x509.CertificateSigningRequestBuilder()

        builder = builder.subject_name(x509_name(subject))
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        request = builder.sign(private_key, hashes.SHA256())

        return private_key, request

    def test_basic(self) -> None:
        """Test a basic CSR info retrieval."""
        for cert_data in [v for v in certs.values() if v["type"] == "cert" and v["cat"] == "generated"]:
            response = self.client.post(self.url, data={"csr": cert_data["csr"]["pem"]})
            self.assertEqual(response.status_code, 200)
            self.assertJSONEqual(response.content, {"subject": cert_data["csr_subject"]})

    def test_fields(self) -> None:
        """Test fetching a CSR with all subject fields."""
        subject = [
            (f, "AT" if f in ("C", "jurisdictionCountryName") else f"test-{f}")
            for f in constants.NAME_OID_NAMES.values()
        ]
        subject_strs = [f"{k}={v}" for k, v in subject]
        csr = self.create_csr("/".join(subject_strs))[1]
        csr_pem = csr.public_bytes(Encoding.PEM).decode("utf-8")

        response = self.client.post(self.url, data={"csr": csr_pem})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            json.loads(response.content.decode("utf-8")),
            {
                "subject": {
                    "C": "AT",
                    "CN": "test-CN",
                    "DC": "test-DC",
                    "L": "test-L",
                    "O": "test-O",
                    "OU": "test-OU",
                    "ST": "test-ST",
                    "emailAddress": "test-emailAddress",
                    "businessCategory": "test-businessCategory",
                    "dnQualifier": "test-dnQualifier",
                    "generationQualifier": "test-generationQualifier",
                    "givenName": "test-givenName",
                    "inn": "test-inn",
                    "jurisdictionCountryName": "AT",
                    "jurisdictionLocalityName": "test-jurisdictionLocalityName",
                    "jurisdictionStateOrProvinceName": "test-jurisdictionStateOrProvinceName",
                    "ogrn": "test-ogrn",
                    "postalAddress": "test-postalAddress",
                    "postalCode": "test-postalCode",
                    "pseudonym": "test-pseudonym",
                    "serialNumber": "test-serialNumber",
                    "sn": "test-sn",
                    "snils": "test-snils",
                    "street": "test-street",
                    "title": "test-title",
                    "uid": "test-uid",
                    "unstructuredName": "test-unstructuredName",
                    "x500UniqueIdentifier": "test-x500UniqueIdentifier",
                }
            },
        )

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


class CADetailsViewTestCase(CertificateModelAdminTestCaseMixin, TestCase):
    """Test fetching CA details."""

    load_cas = ("root", "child", "ed448")
    url = reverse("admin:django_ca_certificate_ca_details")

    @override_tmpcadir()
    @freeze_time(timestamps["everything_valid"])
    def test_basic(self) -> None:
        """Test fetching CA with all kinds of URLs."""

        self.ca.issuer_url = "http://issuer.child.example.com"
        self.ca.ocsp_url = "http://ocsp.child.example.com"
        self.ca.crl_url = "http://crl.child.example.com"
        self.ca.issuer_alt_name = "http://ian.child.example.com"
        self.ca.save()

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()[str(self.ca.pk)],
            {
                "name": self.ca.name,
                "signature_hash_algorithm": constants.HASH_ALGORITHM_NAMES[
                    type(self.ca.algorithm)  # type: ignore[index]
                ],
                "extensions": {
                    "authority_information_access": {
                        "critical": False,
                        "value": {
                            "issuers": [f"URI:{self.ca.issuer_url}"],
                            "ocsp": [f"URI:{self.ca.ocsp_url}"],
                        },
                    },
                    "crl_distribution_points": {
                        "critical": False,
                        "value": [{"full_name": [f"URI:{self.ca.crl_url}"]}],
                    },
                    "issuer_alternative_name": {
                        "critical": False,
                        "value": [f"URI:{self.ca.issuer_alt_name}"],
                    },
                },
            },
        )

        ca = self.cas["ed448"]
        self.assertEqual(
            response.json()[str(ca.pk)],
            {
                "name": ca.name,
                "signature_hash_algorithm": None,
                "extensions": {
                    "authority_information_access": {
                        "critical": False,
                        "value": {
                            "issuers": [f"URI:{ca.issuer_url}"],
                            "ocsp": [f"URI:{ca.ocsp_url}"],
                        },
                    },
                    "crl_distribution_points": {
                        "critical": False,
                        "value": [{"full_name": [f"URI:{ca.crl_url}"]}],
                    },
                },
            },
        )

    @override_tmpcadir()
    @freeze_time(timestamps["everything_valid"])
    def test_empty_ca(self) -> None:
        """Test fetching CA with no URLs."""

        self.ca.issuer_url = ""
        self.ca.ocsp_url = ""
        self.ca.crl_url = ""
        self.ca.issuer_alt_name = ""
        self.ca.save()

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()[str(self.ca.pk)],
            {
                "name": self.ca.name,
                "extensions": {},
                "signature_hash_algorithm": constants.HASH_ALGORITHM_NAMES[
                    type(self.ca.algorithm)  # type: ignore[index]
                ],
            },
        )

    def test_unusable_ca(self) -> None:
        """Test fetching CA with no URLs."""

        self.ca.issuer_url = ""
        self.ca.ocsp_url = ""
        self.ca.crl_url = ""
        self.ca.issuer_alt_name = ""
        self.ca.save()

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(str(self.ca.pk), response.json())


class ProfilesViewTestCase(CertificateModelAdminTestCaseMixin, TestCase):
    """Test fetching profile information."""

    url = reverse("admin:django_ca_certificate_profiles")

    def test_basic(self) -> None:
        """Test fetching basic profile information."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        enduser_desc = "A certificate for an enduser, allows client authentication, code and email signing."

        # Cast elements of subject to list, since actual data is comming from JSON
        expected_subject = [[k, v] for k, v in ca_settings.CA_DEFAULT_SUBJECT]

        self.assertEqual(
            response.json(),
            {
                "client": {
                    "cn_in_san": True,
                    "description": "A certificate for a client.",
                    "extensions": {
                        "basic_constraints": {
                            "critical": True,
                            "value": {"ca": False},
                        },
                        "key_usage": {
                            "critical": True,
                            "value": ["digital_signature"],
                        },
                        "extended_key_usage": {
                            "critical": False,
                            "value": ["clientAuth"],
                        },
                    },
                    "subject": expected_subject,
                },
                "enduser": {
                    "cn_in_san": False,
                    "description": enduser_desc,
                    "extensions": {
                        "basic_constraints": {
                            "critical": True,
                            "value": {"ca": False},
                        },
                        "key_usage": {
                            "critical": True,
                            "value": ["data_encipherment", "digital_signature", "key_encipherment"],
                        },
                        "extended_key_usage": {
                            "critical": False,
                            "value": ["clientAuth", "codeSigning", "emailProtection"],
                        },
                    },
                    "subject": expected_subject,
                },
                "ocsp": {
                    "cn_in_san": False,
                    "description": "A certificate for an OCSP responder.",
                    "extensions": {
                        "basic_constraints": {
                            "critical": True,
                            "value": {"ca": False},
                        },
                        "key_usage": {
                            "critical": True,
                            "value": ["content_commitment", "digital_signature", "key_encipherment"],
                        },
                        "extended_key_usage": {
                            "critical": False,
                            "value": ["OCSPSigning"],
                        },
                    },
                    "subject": expected_subject,
                },
                "server": {
                    "cn_in_san": True,
                    "description": "A certificate for a server, allows client and server authentication.",
                    "extensions": {
                        "basic_constraints": {
                            "critical": True,
                            "value": {"ca": False},
                        },
                        "key_usage": {
                            "critical": True,
                            "value": ["digital_signature", "key_agreement", "key_encipherment"],
                        },
                        "extended_key_usage": {
                            "critical": False,
                            "value": ["clientAuth", "serverAuth"],
                        },
                    },
                    "subject": expected_subject,
                },
                "webserver": {
                    "cn_in_san": True,
                    "description": "A certificate for a webserver.",
                    "extensions": {
                        "basic_constraints": {
                            "critical": True,
                            "value": {"ca": False},
                        },
                        "key_usage": {
                            "critical": True,
                            "value": ["digital_signature", "key_agreement", "key_encipherment"],
                        },
                        "extended_key_usage": {
                            "critical": False,
                            "value": ["serverAuth"],
                        },
                    },
                    "subject": expected_subject,
                },
            },
        )

    def test_permission_denied(self) -> None:
        """Try fetching profiles without permissions."""
        self.user.is_superuser = False
        self.user.save()
        self.assertEqual(self.client.get(self.url).status_code, HTTPStatus.FORBIDDEN)

    # removes all profiles, adds one pretty boring one
    @override_tmpcadir(
        CA_PROFILES={
            "webserver": None,
            "server": None,
            "ocsp": None,
            "enduser": None,
            "client": None,
            "test": {
                "cn_in_san": True,
            },
        },
        CA_DEFAULT_PROFILE="test",
    )
    def test_empty_profile(self) -> None:
        """Try fetching a simple profile."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)

        # Cast elements of subject to list, since actual data is comming from JSON
        expected_subject = [[k, v] for k, v in ca_settings.CA_DEFAULT_SUBJECT]
        self.assertEqual(
            response.json(),
            {
                "test": {
                    "cn_in_san": True,
                    "description": "",
                    "extensions": {
                        "basic_constraints": {
                            "critical": True,
                            "value": {"ca": False},
                        },
                    },
                    "subject": expected_subject,
                },
            },
        )


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
