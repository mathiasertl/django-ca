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

"""Test ACME certificate revocation."""

# pylint: disable=redefined-outer-name  # because of fixtures

import unittest
from collections.abc import Iterator
from datetime import datetime
from http import HTTPStatus
from typing import Any, Optional, Union

import josepy as jose
from acme.messages import Revocation

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from OpenSSL.crypto import X509, X509Req

from django.test import Client
from django.urls import reverse

import pytest
from pytest_django.fixtures import SettingsWrapper

from django_ca.conf import model_settings
from django_ca.constants import ReasonFlags
from django_ca.key_backends.storages import StoragesUsePrivateKeyOptions
from django_ca.models import (
    AcmeAccount,
    AcmeAuthorization,
    AcmeCertificate,
    AcmeOrder,
    Certificate,
    CertificateAuthority,
    acme_slug,
)
from django_ca.tests.acme.views.assertions import assert_malformed, assert_unauthorized
from django_ca.tests.acme.views.base import AcmeWithAccountViewTestCaseMixin
from django_ca.tests.acme.views.utils import acme_request
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS
from django_ca.tests.base.typehints import HttpResponse
from django_ca.tests.base.utils import root_reverse
from django_ca.utils import get_cert_builder

# ACME views require a currently valid certificate authority
pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"]), pytest.mark.usefixtures("acme_cert")]


@pytest.fixture()
def url() -> Iterator[str]:
    """URL under test."""
    yield root_reverse("acme-revoke")


@pytest.fixture()
def message() -> Iterator[Revocation]:
    """Default message sent to the server."""
    default_certificate = CERT_DATA["root-cert"]["pub"]["parsed"]
    return Revocation(certificate=jose.util.ComparableX509(X509.from_cryptography(default_certificate)))


class TestAcmeCertificateRevocationView(AcmeWithAccountViewTestCaseMixin[Revocation]):
    """Test revoking a certificate.

    This class tests requests signed by the account that owns the certificate (so requests with KID).
    """

    class csr_class(Revocation):  # pylint: disable=invalid-name
        """Class that allows us to send a CSR in the certificate field for testing."""

        certificate = jose.json_util.Field(
            "certificate", decoder=jose.json_util.decode_csr, encoder=jose.json_util.encode_csr
        )

    def get_message(self, **kwargs: Any) -> Revocation:
        """Get default message."""
        default_certificate = CERT_DATA["root-cert"]["pub"]["parsed"]
        kwargs.setdefault(
            "certificate", jose.util.ComparableX509(X509.from_cryptography(default_certificate))
        )
        return Revocation(**kwargs)

    @unittest.skip("Not applicable (we accept both JWK and JID).")
    def test_wrong_jwk_or_kid(self) -> None:  # type: ignore[override]
        """Test makes no sense here, as we accept both JWK and JID."""

    def acme(
        self,
        client: Client,
        url: str,
        ca: CertificateAuthority,
        message: Union[bytes, Revocation],
        kid: Optional[str],
    ) -> "HttpResponse":
        """Make an ACME request (override in subclasses)."""
        return acme_request(client, url, ca, message, kid=kid)

    @pytest.mark.parametrize(
        "use_tz, timestamp",
        ((True, TIMESTAMPS["everything_valid"]), (False, TIMESTAMPS["everything_valid_naive"])),
    )
    def test_basic(
        self,
        settings: SettingsWrapper,
        client: Client,
        url: str,
        message: Revocation,
        root_cert: Certificate,
        kid: Optional[str],
        use_tz: bool,
        timestamp: datetime,
    ) -> None:
        """Test a very basic certificate revocation."""
        settings.USE_TZ = use_tz
        resp = self.acme(client, url, root_cert.ca, message, kid=kid)
        assert resp.status_code == HTTPStatus.OK, resp.content

        root_cert.refresh_from_db()
        assert root_cert.revoked is True
        assert root_cert.revoked_date == timestamp
        assert root_cert.revoked_reason == ReasonFlags.unspecified.value

    def test_reason_code(self, client: Client, url: str, root_cert: Certificate, kid: Optional[str]) -> None:
        """Test revocation reason."""
        message = self.get_message(reason=3)
        resp = self.acme(client, url, root_cert.ca, message, kid=kid)
        assert resp.status_code == HTTPStatus.OK, resp.content

        root_cert.refresh_from_db()
        assert root_cert.revoked is True
        assert root_cert.revoked_date == TIMESTAMPS["everything_valid"]
        assert root_cert.revoked_reason == ReasonFlags.affiliation_changed.name

    def test_already_revoked(
        self, client: Client, url: str, message: Revocation, root: CertificateAuthority, kid: str
    ) -> None:
        """Test revoking a certificate that is already revoked."""
        resp = self.acme(client, url, root, message, kid=kid)
        assert resp.status_code == HTTPStatus.OK, resp.content

        resp = self.acme(client, url, root, message, kid=kid)
        assert_malformed(resp, root, "Certificate was already revoked.", typ="alreadyRevoked")

    def test_bad_reason_code(self, client: Client, url: str, root_cert: Certificate, kid: str) -> None:
        """Send a bad revocation reason code to the server."""
        message = self.get_message(reason=99)
        resp = self.acme(client, url, root_cert.ca, message, kid=kid)
        assert_malformed(resp, root_cert.ca, "99: Unsupported revocation reason.", typ="badRevocationReason")

        root_cert.refresh_from_db()
        assert root_cert.revoked is False

    def test_unknown_certificate(
        self, client: Client, url: str, message: Revocation, root: CertificateAuthority, kid: str
    ) -> None:
        """Try sending an unknown certificate to the server."""
        Certificate.objects.all().delete()
        resp = self.acme(client, url, root, message, kid=kid)
        assert_unauthorized(resp, root, "Certificate not found.")

    @pytest.mark.usefixtures("tmpcadir")
    def test_wrong_certificate(
        self, client: Client, url: str, usable_root: CertificateAuthority, root_cert: Certificate, kid: str
    ) -> None:
        """Test sending a different certificate with the same serial."""
        # Create a clone of the existing certificate with the same serial number
        pkey = CERT_DATA["root-cert"]["csr"]["parsed"].public_key()
        builder = get_cert_builder(root_cert.expires, serial=root_cert.pub.loaded.serial_number)
        builder = builder.public_key(pkey)
        builder = builder.issuer_name(root_cert.ca.subject)
        builder = builder.subject_name(root_cert.pub.loaded.subject)
        ca_key = usable_root.key_backend.get_key(  # type: ignore[attr-defined]  # we assume StoragesBackend
            root_cert.ca, StoragesUsePrivateKeyOptions(password=None)
        )
        cert = builder.sign(private_key=ca_key, algorithm=model_settings.CA_DEFAULT_SIGNATURE_HASH_ALGORITHM)
        message = Revocation(certificate=jose.util.ComparableX509(X509.from_cryptography(cert)))

        resp = self.acme(client, url, usable_root, message, kid=kid)
        assert_unauthorized(resp, usable_root, "Certificate does not match records.")

    def test_pass_csr(self, client: Client, url: str, root: CertificateAuthority, kid: str) -> None:
        """Send a CSR instead of a certificate."""
        req = X509Req.from_cryptography(CERT_DATA["root-cert"]["csr"]["parsed"])
        message = self.csr_class(certificate=jose.util.ComparableX509(req))
        resp = self.acme(client, url, root, message, kid=kid)
        assert_malformed(resp, root, "Could not decode 'certificate'", regex=True)


class TestAcmeCertificateRevocationWithAuthorizationsView(TestAcmeCertificateRevocationView):
    """Test certificate revocation by the account holding authorizations to all certificates.

    This class tests a revocation signed by an account that holds active authorizations for all certificates.
    This would be the case if e.g. the domain owner changes and the new owner tries to revoke certificates
    from the old owner (does not have private key or account).
    """

    requires_kid = False

    CHILD_PEM = (
        CERT_DATA["child-cert"]["key"]["parsed"]
        .public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode("utf-8")
        .strip()
    )
    CHILD_THUMBPRINT = "ux-66bpJQiyeDduTWQZHgkB4KJWK0kSdPOabnFiitFM"
    CHILD_SLUG = acme_slug()

    @pytest.fixture()
    def child_kid_fixture(self, root: CertificateAuthority) -> Iterator[str]:
        """Fixture to set compute the child KID."""
        yield self.absolute_uri(":acme-account", serial=root.serial, slug=self.CHILD_SLUG)

    @pytest.fixture(autouse=True)
    def account_two_fixture(
        self, root: CertificateAuthority, account: AcmeAccount, child_kid_fixture: str
    ) -> None:
        """Fixture to set fields for second account."""
        # pylint: disable=attribute-defined-outside-init
        # Set a different slug/kid for the main account, as we have to overwrite the "kid" fixture for the
        # test cases from the base class, but the fixture is also used to create the account.
        account.slug = acme_slug()
        account.kid = self.absolute_uri(":acme-account", serial=root.serial, slug=account.slug)
        account.save()

        self.child_kid = child_kid_fixture
        self.account2 = AcmeAccount.objects.create(
            ca=root,
            contact="mailto:two@example.net",
            terms_of_service_agreed=True,
            slug=self.CHILD_SLUG,
            kid=child_kid_fixture,
            pem=self.CHILD_PEM,
            thumbprint=self.CHILD_THUMBPRINT,
        )
        self.acme_order = AcmeOrder.objects.create(account=self.account2)
        self.acme_auth = AcmeAuthorization.objects.create(
            order=self.acme_order, value="root-cert.example.com", status=AcmeAuthorization.STATUS_VALID
        )

    def acme(  # type: ignore[override]
        self,
        client: Client,
        url: str,
        ca: CertificateAuthority,
        message: Revocation,
        kid: str = "",  # value is ignored by the function
    ) -> "HttpResponse":
        return acme_request(
            client,
            url,
            ca,
            message,
            cert=CERT_DATA["child-cert"]["key"]["parsed"],
            kid=self.child_kid,
        )

    @pytest.fixture()
    def main_account(self) -> AcmeAccount:  # type: ignore[override]
        return self.account2

    @unittest.skip("Test only tests base functionality, but does not work with unusual KID/JWK setup.")
    def test_unknown_account(self) -> None:  # type: ignore[override]
        pass

    @unittest.skip("Test only tests base functionality, but does not work with unusual KID/JWK setup.")
    def test_unknown_nonce(self) -> None:  # type: ignore[override]
        pass

    @unittest.skip("Test only tests base functionality, but does not work with unusual KID/JWK setup.")
    def test_duplicate_nonce(self) -> None:  # type: ignore[override]
        pass

    @unittest.skip("Test only tests base functionality, but does not work with unusual KID/JWK setup.")
    def test_wrong_url(self) -> None:  # type: ignore[override]
        pass

    @pytest.fixture()
    def kid(self, child_kid_fixture: str) -> Iterator[Optional[str]]:
        """Override kid to return the child kid."""
        yield child_kid_fixture

    def test_wrong_authorizations(self, client: Client, url: str, root: CertificateAuthority) -> None:
        """Test revoking a certificate when the account has some, but the wrong authorizations."""
        self.acme_auth.value = "wrong.example.com"
        self.acme_auth.save()

        resp = self.acme(client, url, root, self.get_message())
        assert_unauthorized(resp, root, "Account does not hold necessary authorizations.")

    def test_no_extensions(
        self, client: Client, child: CertificateAuthority, no_extensions: Certificate, account: AcmeAccount
    ) -> None:
        """Test revoking a certificate that has no SubjectAltName extension."""
        # Since no_extensions is signed by child, we have to update the account
        self.account2.ca = child
        self.account2.save()

        # Create AcmeOrder/Certificate (only certs issued via ACME can be revoked via ACME).
        order = AcmeOrder.objects.create(account=account, status=AcmeOrder.STATUS_VALID)
        AcmeCertificate.objects.create(order=order, cert=no_extensions)

        url = reverse("django_ca:acme-revoke", kwargs={"serial": CERT_DATA["child"]["serial"]})
        message_cert = jose.util.ComparableX509(X509.from_cryptography(no_extensions.pub.loaded))
        resp = self.acme(client, url, child, self.get_message(certificate=message_cert))
        assert_unauthorized(resp, child, "Account does not hold necessary authorizations.")

    def test_non_dns_sans(
        self, client: Client, child: CertificateAuthority, alt_extensions: Certificate, account: AcmeAccount
    ) -> None:
        """Test revoking a certificate that has no SubjectAltName extension."""
        # Since alt_extensions is signed by child, we have to update the account
        self.account2.ca = child
        self.account2.save()

        # Create AcmeOrder/Certificate (only certs issued via ACME can be revoked via ACME).
        order = AcmeOrder.objects.create(account=account, status=AcmeOrder.STATUS_VALID)
        AcmeCertificate.objects.create(order=order, cert=alt_extensions)

        url = reverse("django_ca:acme-revoke", kwargs={"serial": CERT_DATA["child"]["serial"]})
        message_cert = jose.util.ComparableX509(X509.from_cryptography(alt_extensions.pub.loaded))
        resp = self.acme(client, url, child, self.get_message(certificate=message_cert))
        assert_unauthorized(resp, child, "Certificate contains non-DNS subjectAlternativeNames.")


class TestAcmeCertificateRevocationWithJWKView(TestAcmeCertificateRevocationView):
    """Test certificate revocation by signing the request with the compromised certificate.

    Tests requests signed by the private key of the certificate.
    """

    def acme(
        self,
        client: Client,
        url: str,
        ca: CertificateAuthority,
        message: Union[bytes, Revocation],
        kid: Optional[str],
    ) -> "HttpResponse":
        return acme_request(client, url, ca, message, kid=None)

    def test_wrong_signer(
        self, client: Client, url: str, message: Revocation, root: CertificateAuthority
    ) -> None:
        """Sign the request with the wrong certificate."""
        cert = CERT_DATA["child-cert"]["key"]["parsed"]
        resp = acme_request(client, url, root, message, cert=cert, kid=None)
        assert_unauthorized(resp, root, "Request signed by the wrong certificate.")

    @unittest.skip("Not applicable.")
    def test_tos_not_agreed_account(self) -> None:  # type: ignore[override]
        """Not applicable: Certificate-signed revocation requests do not require a valid account."""

    @unittest.skip("Not applicable.")
    def test_deactivated_account(self) -> None:  # type: ignore[override]
        """Not applicable: Certificate-signed revocation requests do not require a valid account."""

    @unittest.skip("Not applicable.")
    def test_unknown_account(self) -> None:  # type: ignore[override]
        """Not applicable: Certificate-signed revocation requests do not require a valid account."""

    @unittest.skip("Not applicable.")
    def test_unusable_account(self) -> None:  # type: ignore[override]
        """Not applicable: Certificate-signed revocation requests do not require a valid account."""

    @unittest.skip("Not applicable.")
    def test_jwk_and_kid(self) -> None:  # type: ignore[override]
        """Not applicable: Already tested in the immediate base class and does not make sense here.

        The test sets KID to a value, but the point of the whole class is to have *no* KID.
        """
