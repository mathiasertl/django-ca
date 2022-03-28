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
# see <http://www.gnu.org/licenses/>

"""Base test cases for admin views and CertificateAdmin tests."""

import json
import typing
from http import HTTPStatus

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.http import HttpResponse
from django.test import Client
from django.test import TestCase
from django.urls import reverse

from freezegun import freeze_time

from .. import ca_settings
from ..models import Certificate
from ..models import CertificateAuthority
from ..models import Watcher
from ..subject import Subject
from ..typehints import PrivateKeyTypes
from ..utils import OID_NAME_MAPPINGS
from ..utils import x509_name
from .base import certs
from .base import override_tmpcadir
from .base import timestamps
from .base.mixins import AdminTestCaseMixin
from .base.mixins import StandardAdminViewTestCaseMixin

User = get_user_model()


class CertificateAdminTestCaseMixin:
    """Mixin that defines the ``media_css`` property for certificates.

    This does **not** set the ``model`` property, as mypy then complains about incompatible types in base
    classes.
    """

    media_css: typing.Tuple[str, ...] = (
        "django_ca/admin/css/base.css",
        "django_ca/admin/css/certificateadmin.css",
    )


class CertificateModelAdminTestCaseMixin(CertificateAdminTestCaseMixin, AdminTestCaseMixin[Certificate]):
    """Specialized variant of :py:class:`~django_ca.tests.tests_admin.AdminTestCaseMixin` for certificates."""

    model = Certificate


@freeze_time(timestamps["everything_valid"])
class CertificateAdminViewTestCase(
    CertificateAdminTestCaseMixin, StandardAdminViewTestCaseMixin[Certificate], TestCase
):
    """Tests for the Certificate ModelAdmin class."""

    load_cas = "__usable__"
    load_certs = "__usable__"
    model = Certificate

    def assertChangeResponse(  # pylint: disable=invalid-name,missing-function-docstring
        self, response: HttpResponse, obj: Certificate, status: int = HTTPStatus.OK
    ) -> None:
        super().assertChangeResponse(response, obj=obj, status=status)

        prefix = f"admin:{obj._meta.app_label}_{obj._meta.model_name}"
        url = reverse(f"{prefix}_download", kwargs={"pk": obj.pk})
        bundle_url = reverse(f"{prefix}_download_bundle", kwargs={"pk": obj.pk})
        text = response.content.decode()
        pem = obj.pub.pem.replace("\n", "<br>")  # newlines are replaced with HTML linebreaks by Django
        self.assertInHTML(f"<div class='readonly'>{pem}</div>", text, 1)
        self.assertInHTML(f"<a href='{url}?format=PEM'>as PEM</a>", text, 1)
        self.assertInHTML(f"<a href='{url}?format=DER'>as DER</a>", text, 1)
        self.assertInHTML(f"<a href='{bundle_url}?format=PEM'>as PEM</a>", text, 1)

    def get_changelists(
        self,
    ) -> typing.Iterator[typing.Tuple[typing.Iterable[Certificate], typing.Dict[str, str]]]:
        # yield various different result sets for different filters and times
        with self.freeze_time("everything_valid"):
            yield (self.model.objects.all(), {})
            yield (self.model.objects.all(), {"status": "valid"})
            yield (self.model.objects.all(), {"status": "all"})
            yield ([], {"status": "expired"})
            yield ([], {"status": "revoked"})

            yield ([], {"auto": "auto"})
            yield (self.model.objects.all(), {"auto": "all"})

        with self.freeze_time("ca_certs_expired"):
            yield (self.model.objects.all(), {"status": "all"})
            yield [
                self.certs["profile-client"],
                self.certs["profile-server"],
                self.certs["profile-webserver"],
                self.certs["profile-enduser"],
                self.certs["profile-ocsp"],
                self.certs["no-extensions"],
                self.certs["all-extensions"],
                self.certs["alt-extensions"],
            ], {}
            yield [
                self.certs["root-cert"],
                self.certs["pwd-cert"],
                self.certs["ecc-cert"],
                self.certs["dsa-cert"],
                self.certs["child-cert"],
            ], {"status": "expired"}
            yield [], {"status": "revoked"}

        with self.freeze_time("everything_expired"):
            yield ([], {})  # default view shows nothing - everything is expired
            yield (self.model.objects.all(), {"status": "all"})
            yield (self.model.objects.all(), {"status": "expired"})

        # load all certs (including 3rd party certs) and view with status_all
        with self.freeze_time("everything_valid"):
            self.load_named_cas("__all__")
            self.load_named_certs("__all__")
            yield (self.model.objects.all(), {"status": "all"})

            # now revoke all certs, to test that filter
            self.model.objects.update(revoked=True)
            yield (self.model.objects.all(), {"status": "all"})
            yield (self.model.objects.all(), {"status": "revoked"})
            yield ([], {})  # default shows nothing - everything expired

            # unrevoke all certs, but set one of them as auto-generated
            self.model.objects.update(revoked=False)
            self.certs["profile-ocsp"].autogenerated = True
            self.certs["profile-ocsp"].save()

            yield ([self.certs["profile-ocsp"]], {"auto": "auto"})
            yield (self.model.objects.all(), {"auto": "all", "status": "all"})

    def test_change_view(self) -> None:
        self.load_named_cas("__all__")
        self.load_named_certs("__all__")
        super().test_change_view()

    def test_revoked(self) -> None:
        """View a revoked certificate (fieldset should be collapsed)."""
        self.certs["root-cert"].revoke()

        response = self.client.get(self.change_url())
        self.assertChangeResponse(response, obj=self.certs["root-cert"])

        self.assertContains(
            response,
            text="""<div class="fieldBox field-revoked"><label>Revoked:</label>
                     <div class="readonly"><img src="/static/admin/img/icon-yes.svg" alt="True"></div>
                </div>""",
            html=True,
        )

    def test_no_san(self) -> None:
        """Test viewing a certificate with no extensions."""
        cert = self.certs["no-extensions"]
        response = self.client.get(cert.admin_change_url)
        self.assertChangeResponse(response, obj=cert)
        self.assertContains(
            response,
            text="""
<div class="form-row field-oid_2_5_29_17">
    <div>
        <label>SubjectAlternativeName:</label>
        <div class="readonly">
            <span class="django-ca-extension">
                <div class="django-ca-extension-value">
                    &lt;Not present&gt;
                </div>
            </span>
        </div>
    </div>
</div>
""",
            html=True,
        )

    def test_change_watchers(self) -> None:
        """Test changing watchers.

        NOTE: This only tests standard Django functionality, BUT save_model() has special handling when
        creating a new object (=sign a new cert). So we have to test saving a cert that already exists for
        code coverage.
        """
        cert = self.certs["root-cert"]
        cert = Certificate.objects.get(serial=cert.serial)
        watcher = Watcher.objects.create(name="User", mail="user@example.com")

        response = self.client.post(
            self.change_url(),
            data={
                "watchers": [watcher.pk],
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, self.changelist_url)
        self.assertEqual(list(cert.watchers.all()), [watcher])


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
            for f in OID_NAME_MAPPINGS.values()
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


class ProfilesViewTestCase(CertificateModelAdminTestCaseMixin, TestCase):
    """Test fetching profile information."""

    url = reverse("admin:django_ca_certificate_profiles")

    def test_basic(self) -> None:
        """Test fetching basic profile information."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        enduser_desc = "A certificate for an enduser, allows client authentication, code and email signing."
        self.assertEqual(
            json.loads(response.content.decode("utf-8")),
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
                            "value": ["digitalSignature"],
                        },
                        "extended_key_usage": {
                            "critical": False,
                            "value": ["clientAuth"],
                        },
                    },
                    "subject": dict(Subject(ca_settings.CA_DEFAULT_SUBJECT)),
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
                            "value": [
                                "dataEncipherment",
                                "digitalSignature",
                                "keyEncipherment",
                            ],
                        },
                        "extended_key_usage": {
                            "critical": False,
                            "value": ["clientAuth", "codeSigning", "emailProtection"],
                        },
                    },
                    "subject": dict(Subject(ca_settings.CA_DEFAULT_SUBJECT)),
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
                            "value": ["digitalSignature", "keyEncipherment", "nonRepudiation"],
                        },
                        "extended_key_usage": {
                            "critical": False,
                            "value": ["OCSPSigning"],
                        },
                    },
                    "subject": dict(Subject(ca_settings.CA_DEFAULT_SUBJECT)),
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
                            "value": [
                                "digitalSignature",
                                "keyAgreement",
                                "keyEncipherment",
                            ],
                        },
                        "extended_key_usage": {
                            "critical": False,
                            "value": ["clientAuth", "serverAuth"],
                        },
                    },
                    "subject": dict(Subject(ca_settings.CA_DEFAULT_SUBJECT)),
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
                            "value": [
                                "digitalSignature",
                                "keyAgreement",
                                "keyEncipherment",
                            ],
                        },
                        "extended_key_usage": {
                            "critical": False,
                            "value": ["serverAuth"],
                        },
                    },
                    "subject": dict(Subject(ca_settings.CA_DEFAULT_SUBJECT)),
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
        }
    )
    def test_empty_profile(self) -> None:
        """Try fetching a simple profile."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            json.loads(response.content.decode("utf-8")),
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
                    "subject": dict(Subject(ca_settings.CA_DEFAULT_SUBJECT)),
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
