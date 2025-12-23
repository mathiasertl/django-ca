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

"""Test Django model classes."""

import typing

from acme import challenges, messages

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db.utils import IntegrityError
from django.test import RequestFactory, TestCase, override_settings
from django.utils import timezone

import pytest
from freezegun import freeze_time

from django_ca.key_backends.storages.models import StoragesUsePrivateKeyOptions
from django_ca.modelfields import LazyCertificate, LazyCertificateSigningRequest
from django_ca.models import (
    AcmeAccount,
    AcmeAuthorization,
    AcmeCertificate,
    AcmeChallenge,
    AcmeOrder,
    Certificate,
    Watcher,
)
from django_ca.tests.base.assertions import assert_validation_error
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS
from django_ca.tests.base.mixins import AcmeValuesMixin, TestCaseMixin

ChallengeTypeVar = typing.TypeVar("ChallengeTypeVar", bound=challenges.KeyAuthorizationChallenge)
key_backend_options = StoragesUsePrivateKeyOptions(password=None)


class TestWatcher(TestCase):
    """Test :py:class:`django_ca.models.Watcher`."""

    def test_from_addr(self) -> None:
        """Basic test for the ``from_addr()`` function."""
        mail = "user@example.com"
        name = "Firstname Lastname"

        watcher = Watcher.from_addr(f"{name} <{mail}>")
        assert watcher.mail == mail
        assert watcher.name == name

    def test_spaces(self) -> None:
        """Test that ``from_addr() is agnostic to spaces."""
        mail = "user@example.com"
        name = "Firstname Lastname"

        watcher = Watcher.from_addr(f"{name}     <{mail}>")
        assert watcher.mail == mail
        assert watcher.name == name

        watcher = Watcher.from_addr(f"{name}<{mail}>")
        assert watcher.mail == mail
        assert watcher.name == name

    def test_error(self) -> None:
        """Test some validation errors."""
        with pytest.raises(ValidationError):
            Watcher.from_addr("foobar ")
        with pytest.raises(ValidationError):
            Watcher.from_addr("foobar @")

    def test_update(self) -> None:
        """Test that from_addr updates the name if passed."""
        mail = "user@example.com"
        name = "Firstname Lastname"
        newname = "Newfirst Newlast"

        Watcher.from_addr(f"{name} <{mail}>")
        watcher = Watcher.from_addr(f"{newname} <{mail}>")
        assert watcher.mail == mail
        assert watcher.name == newname

    def test_str(self) -> None:
        """Test the str function."""
        mail = "user@example.com"
        name = "Firstname Lastname"

        watcher = Watcher(mail=mail)
        assert str(watcher) == mail

        watcher.name = name
        assert str(watcher) == f"{name} <{mail}>"


class ModelfieldsTests(TestCaseMixin, TestCase):
    """Specialized tests for model fields."""

    csr = CERT_DATA["root-cert"]["csr"]
    pub = CERT_DATA["root-cert"]["pub"]
    load_cas = ("root",)

    def test_create_pem_bytes(self) -> None:
        """Test creating with bytes-encoded PEM."""
        pub = self.pub["pem"].encode()
        csr = self.csr["parsed"].public_bytes(Encoding.PEM)
        cert = Certificate.objects.create(
            pub=pub,
            csr=csr,
            ca=self.ca,
            not_after=timezone.now(),
            not_before=timezone.now(),
        )
        assert cert.pub == pub
        assert cert.csr == csr

        # Refresh, so that we get lazy values
        cert.refresh_from_db()

        assert cert.pub.loaded == self.pub["parsed"]
        assert cert.csr.loaded == self.csr["parsed"]

    def test_create_bytearray(self) -> None:
        """Test creating with bytes-encoded PEM."""
        pub = bytearray(self.pub["der"])
        csr = bytearray(self.csr["parsed"].public_bytes(Encoding.DER))
        cert = Certificate.objects.create(
            pub=pub,  # type: ignore[misc] # what we test
            csr=csr,
            ca=self.ca,
            not_after=timezone.now(),
            not_before=timezone.now(),
        )
        assert cert.pub == pub
        assert cert.csr == csr

        # Refresh, so that we get lazy values
        cert.refresh_from_db()

        assert cert.pub.loaded == self.pub["parsed"]
        assert cert.csr.loaded == self.csr["parsed"]

    def test_create_memoryview(self) -> None:
        """Test creating with bytes-encoded PEM."""
        pub = memoryview(self.pub["der"])
        csr = memoryview(self.csr["parsed"].public_bytes(Encoding.DER))
        cert = Certificate.objects.create(
            pub=pub,  # type: ignore[misc]
            csr=csr,
            ca=self.ca,
            not_after=timezone.now(),
            not_before=timezone.now(),
        )
        assert cert.pub == pub
        assert cert.csr == csr

        # Refresh, so that we get lazy values
        cert.refresh_from_db()

        assert cert.pub.loaded == self.pub["parsed"]
        assert cert.csr.loaded == self.csr["parsed"]

    def test_create_from_instance(self) -> None:
        """Test creating a certificate from LazyField instances."""
        loaded = self.load_named_cert("root-cert")
        assert isinstance(loaded.pub, LazyCertificate)
        assert isinstance(loaded.csr, LazyCertificateSigningRequest)
        cert = Certificate.objects.create(
            pub=loaded.pub,
            csr=loaded.csr,
            ca=self.ca,
            not_after=timezone.now(),
            not_before=timezone.now(),
        )
        assert loaded.pub == cert.pub
        assert loaded.csr == cert.csr

        reloaded = Certificate.objects.get(pk=cert.pk)
        assert loaded.pub == reloaded.pub
        assert loaded.csr == reloaded.csr

    def test_repr(self) -> None:
        """Test ``repr()`` for custom modelfields."""
        cert = Certificate.objects.create(
            pub=self.pub["pem"],
            csr=self.csr["parsed"].public_bytes(Encoding.PEM).decode("utf-8"),
            ca=self.ca,
            not_after=timezone.now(),
            not_before=timezone.now(),
        )
        cert.refresh_from_db()

        subject = "CN=root-cert.example.com,OU=Django CA Testsuite,O=Django CA,L=Vienna,ST=Vienna,C=AT"
        assert repr(cert.pub) == f"<LazyCertificate: {subject}>"
        assert repr(cert.csr) == "<LazyCertificateSigningRequest: CN=csr.root-cert.example.com>"

    def test_none_value(self) -> None:
        """Test that nullable fields work."""
        cert = Certificate.objects.create(
            pub=self.pub["parsed"],
            csr=None,  # type: ignore[misc]  # what we test
            ca=self.ca,
            not_after=timezone.now(),
            not_before=timezone.now(),
        )
        assert cert.csr is None
        cert.refresh_from_db()
        assert cert.csr is None

    def test_filter(self) -> None:
        """Test that we can use various representations for filtering."""
        cert = Certificate.objects.create(
            pub=self.pub["parsed"],
            csr=self.csr["parsed"],
            ca=self.ca,
            not_after=timezone.now(),
            not_before=timezone.now(),
        )

        for prop in ["parsed", "pem", "der"]:
            qs = Certificate.objects.filter(pub=self.pub[prop])
            assert list(qs) == [cert]
            assert qs[0].pub.der == self.pub["der"]

    def test_full_clean(self) -> None:
        """Test the full_clean() method, which invokes ``to_python()`` on the field."""
        cert = Certificate(
            pub=self.pub["parsed"],
            csr=self.csr["parsed"],
            ca=self.ca,
            not_after=timezone.now(),
            not_before=timezone.now(),
            cn="foo",
            serial="1",
        )
        cert.full_clean()
        assert cert.pub.loaded == self.pub["parsed"]
        assert cert.csr.loaded == self.csr["parsed"]

        cert = Certificate(
            pub=cert.pub,
            csr=cert.csr,
            ca=self.ca,
            not_after=timezone.now(),
            not_before=timezone.now(),
            cn="foo",
            serial="1",
        )
        cert.full_clean()
        assert cert.pub.loaded == self.pub["parsed"]
        assert cert.csr.loaded == self.csr["parsed"]

    def test_empty_csr(self) -> None:
        """Test an empty CSR."""
        cert = Certificate(
            pub=self.pub["parsed"],
            csr="",
            ca=self.ca,
            not_after=timezone.now(),
            not_before=timezone.now(),
            cn="foo",
            serial="1",
        )
        cert.full_clean()
        assert cert.pub.loaded == self.pub["parsed"]
        assert cert.csr is None

    def test_invalid_value(self) -> None:
        """Test passing invalid values."""
        with pytest.raises(ValueError, match=r"^True: Could not parse CertificateSigningRequest$"):
            Certificate.objects.create(
                pub=CERT_DATA["child-cert"]["pub"]["parsed"],
                csr=True,  # type: ignore[misc]  # what we test
                ca=self.ca,
                not_after=timezone.now(),
                not_before=timezone.now(),
            )

        with pytest.raises(ValueError, match=r"^True: Could not parse Certificate$"):
            Certificate.objects.create(
                csr=CERT_DATA["child-cert"]["csr"]["parsed"],
                pub=True,  # type: ignore[misc]  # what we test
                ca=self.ca,
                not_after=timezone.now(),
                not_before=timezone.now(),
            )


class AcmeAccountTestCase(TestCaseMixin, AcmeValuesMixin, TestCase):
    """Test :py:class:`django_ca.models.AcmeAccount`."""

    load_cas = ("root", "child")

    def setUp(self) -> None:
        super().setUp()

        self.kid1 = self.absolute_uri(":acme-account", serial=self.cas["root"].serial, slug=self.ACME_SLUG_1)
        self.account1 = AcmeAccount.objects.create(
            ca=self.cas["root"],
            contact="mailto:user@example.com",
            terms_of_service_agreed=True,
            status=AcmeAccount.STATUS_VALID,
            pem=self.ACME_PEM_1,
            thumbprint=self.ACME_THUMBPRINT_1,
            slug=self.ACME_SLUG_1,
            kid=self.kid1,
        )
        self.kid2 = self.absolute_uri(":acme-account", serial=self.cas["child"].serial, slug=self.ACME_SLUG_2)
        self.account2 = AcmeAccount.objects.create(
            ca=self.cas["child"],
            contact="mailto:user@example.net",
            terms_of_service_agreed=False,
            status=AcmeAccount.STATUS_REVOKED,
            pem=self.ACME_PEM_2,
            thumbprint=self.ACME_THUMBPRINT_2,
            slug=self.ACME_SLUG_2,
            kid=self.kid2,
        )

    def test_str(self) -> None:
        """Test str() function."""
        assert str(self.account1) == "user@example.com"
        assert str(self.account2) == "user@example.net"
        assert str(AcmeAccount()) == ""

    def test_serial(self) -> None:
        """Test the ``serial`` property."""
        assert self.account1.serial == self.cas["root"].serial
        assert self.account2.serial == self.cas["child"].serial

        # pylint: disable=no-member; false positive: pylint does not detect RelatedObjectDoesNotExist member
        with pytest.raises(AcmeAccount.ca.RelatedObjectDoesNotExist, match=r"^AcmeAccount has no ca\.$"):
            AcmeAccount().serial  # noqa: B018

    @freeze_time(TIMESTAMPS["everything_valid"])
    def test_usable(self) -> None:
        """Test the ``usable`` property."""
        assert self.account1.usable
        assert not self.account2.usable

        # Try states that make an account **unusable**
        self.account1.status = AcmeAccount.STATUS_DEACTIVATED
        assert not self.account1.usable
        self.account1.status = AcmeAccount.STATUS_REVOKED
        assert not self.account1.usable

        # Make the account usable again
        self.account1.status = AcmeAccount.STATUS_VALID
        assert self.account1.usable

        # TOS not agreed, but CA does not have any
        self.account1.terms_of_service_agreed = False
        assert self.account1.usable

        # TOS not agreed, but CA does have them, so account is now unusable
        self.cas["root"].terms_of_service = "http://tos.example.com"
        self.cas["root"].save()
        assert not self.account1.usable

        # Make the account usable again
        self.account1.terms_of_service_agreed = True
        assert self.account1.usable

        # If the CA is not usable, neither is the account
        self.account1.ca.enabled = False
        assert not self.account1.usable

    @override_settings(ALLOWED_HOSTS=["kid-test.example.net"])
    def test_set_kid(self) -> None:
        """Test set_kid()."""
        hostname = settings.ALLOWED_HOSTS[0]
        req = RequestFactory().get("/foobar", HTTP_HOST=hostname)
        self.account1.set_kid(req)
        assert (
            self.account1.kid
            == f"http://{hostname}/django_ca/acme/{self.account1.serial}/acct/{self.account1.slug}/"
        )

    def test_validate_pem(self) -> None:
        """Test the PEM validator."""
        self.account1.full_clean()

        # So far we only test first and last line, so we just append/prepend a character
        self.account1.pem = f"x{self.account1.pem}"
        with assert_validation_error({"pem": ["Not a valid PEM."]}):
            self.account1.full_clean()

        self.account1.pem = f"{self.account1.pem}x"[1:]
        with assert_validation_error({"pem": ["Not a valid PEM."]}):
            self.account1.full_clean()


class AcmeOrderTestCase(TestCaseMixin, AcmeValuesMixin, TestCase):
    """Test :py:class:`django_ca.models.AcmeOrder`."""

    load_cas = ("root",)

    def setUp(self) -> None:
        super().setUp()
        self.account = AcmeAccount.objects.create(
            ca=self.cas["root"],
            contact="mailto:user@example.com",
            terms_of_service_agreed=True,
            status=AcmeAccount.STATUS_VALID,
            pem=self.ACME_PEM_1,
            thumbprint=self.ACME_THUMBPRINT_1,
        )
        self.order1 = AcmeOrder.objects.create(account=self.account)

    def test_str(self) -> None:
        """Test the str function."""
        assert str(self.order1) == f"{self.order1.slug} ({self.account})"

    def test_acme_url(self) -> None:
        """Test the acme url function."""
        assert self.order1.acme_url == f"/django_ca/acme/{self.account.ca.serial}/order/{self.order1.slug}/"

    def test_acme_finalize_url(self) -> None:
        """Test the acme finalize url function."""
        assert (
            self.order1.acme_finalize_url
            == f"/django_ca/acme/{self.account.ca.serial}/order/{self.order1.slug}/finalize/"
        )

    def test_add_authorizations(self) -> None:
        """Test the add_authorizations method."""
        identifier = messages.Identifier(typ=messages.IDENTIFIER_FQDN, value="example.com")
        auths = self.order1.add_authorizations([identifier])
        assert auths[0].type == "dns"
        assert auths[0].value == "example.com"

        if settings.DATABASE_BACKEND == "sqlite":
            msg = r"^UNIQUE constraint failed: django_ca_acmeauthorization\.order_id, django_ca_acmeauthorization\.type, django_ca_acmeauthorization\.value$"  # NOQA: E501
        elif settings.DATABASE_BACKEND == "postgres":
            msg = r"duplicate key value violates unique constraint"
        elif settings.DATABASE_BACKEND == "mariadb":
            msg = "Duplicate entry"
        else:
            raise ValueError(f"{settings.DATABASE_BACKEND}: Unknown database backend.")
        with pytest.raises(IntegrityError, match=msg):
            self.order1.add_authorizations([identifier])

    def test_serial(self) -> None:
        """Test getting the serial of the associated CA."""
        assert self.order1.serial == self.cas["root"].serial


class AcmeAuthorizationTestCase(TestCaseMixin, AcmeValuesMixin, TestCase):
    """Test :py:class:`django_ca.models.AcmeAuthorization`."""

    load_cas = ("root",)

    def setUp(self) -> None:
        super().setUp()
        self.account = AcmeAccount.objects.create(
            ca=self.cas["root"],
            contact="user@example.com",
            terms_of_service_agreed=True,
            status=AcmeAccount.STATUS_VALID,
            pem=self.ACME_PEM_1,
            thumbprint=self.ACME_THUMBPRINT_1,
        )
        self.order = AcmeOrder.objects.create(account=self.account)
        self.auth1 = AcmeAuthorization.objects.create(
            order=self.order, type=AcmeAuthorization.TYPE_DNS, value="example.com"
        )
        self.auth2 = AcmeAuthorization.objects.create(
            order=self.order, type=AcmeAuthorization.TYPE_DNS, value="example.net"
        )

    def test_str(self) -> None:
        """Test the __str__ method."""
        assert str(self.auth1) == "dns: example.com"
        assert str(self.auth2) == "dns: example.net"

    def test_account_property(self) -> None:
        """Test the account property."""
        assert self.auth1.account == self.account
        assert self.auth2.account == self.account

    def test_acme_url(self) -> None:
        """Test acme_url property."""
        assert self.auth1.acme_url == f"/django_ca/acme/{self.cas['root'].serial}/authz/{self.auth1.slug}/"
        assert self.auth2.acme_url == f"/django_ca/acme/{self.cas['root'].serial}/authz/{self.auth2.slug}/"

    def test_expires(self) -> None:
        """Test the expires property."""
        assert self.auth1.expires == self.order.expires
        assert self.auth2.expires == self.order.expires

    def test_identifier(self) -> None:
        """Test the identifier property."""
        assert self.auth1.identifier == messages.Identifier(
            typ=messages.IDENTIFIER_FQDN, value=self.auth1.value
        )
        assert self.auth2.identifier == messages.Identifier(
            typ=messages.IDENTIFIER_FQDN, value=self.auth2.value
        )

    def test_identifier_unknown_type(self) -> None:
        """Test that an identifier with an unknown type raises a ValueError."""
        self.auth1.type = "foo"
        with pytest.raises(ValueError, match=r"^Unknown identifier type: foo$"):
            self.auth1.identifier  # noqa: B018

    def test_subject_alternative_name(self) -> None:
        """Test the subject_alternative_name property."""
        assert self.auth1.subject_alternative_name == "dns:example.com"
        assert self.auth2.subject_alternative_name == "dns:example.net"

    def test_get_challenges(self) -> None:
        """Test the get_challenges() method."""
        chall_qs = self.auth1.get_challenges()
        assert isinstance(chall_qs[0], AcmeChallenge)
        assert isinstance(chall_qs[1], AcmeChallenge)

        assert self.auth1.get_challenges() == chall_qs
        assert AcmeChallenge.objects.all().count() == 2


class AcmeChallengeTestCase(TestCaseMixin, AcmeValuesMixin, TestCase):
    """Test :py:class:`django_ca.models.AcmeChallenge`."""

    load_cas = ("root",)

    def setUp(self) -> None:
        super().setUp()
        self.account = AcmeAccount.objects.create(
            ca=self.cas["root"],
            contact="user@example.com",
            terms_of_service_agreed=True,
            status=AcmeAccount.STATUS_VALID,
            pem=self.ACME_PEM_1,
            thumbprint=self.ACME_THUMBPRINT_1,
        )
        self.order = AcmeOrder.objects.create(account=self.account)
        self.auth = AcmeAuthorization.objects.create(
            order=self.order, type=AcmeAuthorization.TYPE_DNS, value=self.hostname
        )
        self.chall = AcmeChallenge.objects.create(auth=self.auth, type=AcmeChallenge.TYPE_HTTP_01)

    def assertChallenge(  # pylint: disable=invalid-name
        self, challenge: ChallengeTypeVar, typ: str, token: bytes, cls: type[ChallengeTypeVar]
    ) -> None:
        """Test that the ACME challenge is of the given type."""
        assert isinstance(challenge, cls)
        assert challenge.typ == typ
        assert challenge.token == token

    def test_str(self) -> None:
        """Test the __str__ method."""
        assert str(self.chall) == f"{self.hostname} ({self.chall.type})"

    def test_acme_url(self) -> None:
        """Test acme_url property."""
        assert self.chall.acme_url == f"/django_ca/acme/{self.chall.serial}/chall/{self.chall.slug}/"

    def test_acme_challenge(self) -> None:
        """Test acme_challenge property."""
        self.assertChallenge(
            self.chall.acme_challenge, "http-01", self.chall.token.encode(), challenges.HTTP01
        )

        self.chall.type = AcmeChallenge.TYPE_DNS_01
        self.assertChallenge(self.chall.acme_challenge, "dns-01", self.chall.token.encode(), challenges.DNS01)

        self.chall.type = "foo"
        with pytest.raises(ValueError, match=r"^foo: Unsupported challenge type\.$"):
            self.chall.acme_challenge  # noqa: B018

    @freeze_time(TIMESTAMPS["everything_valid"])
    def test_acme_validated(self) -> None:
        """Test acme_validated property."""
        # preconditions for checks (might change them in setUp without realising it might affect this test)
        assert self.chall.status != AcmeChallenge.STATUS_VALID
        assert self.chall.validated is None

        assert self.chall.acme_validated is None

        self.chall.status = AcmeChallenge.STATUS_VALID
        assert self.chall.acme_validated is None  # still None (no validated timestamp)

        self.chall.validated = timezone.now()
        assert self.chall.acme_validated == TIMESTAMPS["everything_valid"]

        # We return a UTC timestamp, even if timezone support is disabled.
        with self.settings(USE_TZ=False):
            self.chall.validated = timezone.now()
            assert self.chall.acme_validated == TIMESTAMPS["everything_valid"]

    def test_encoded(self) -> None:
        """Test the encoded property."""
        self.chall.token = "ADwFxCAXrnk47rcCnnbbtGYSo_l61MCYXqtBziPt26mk7-QzpYNNKnTsKjbBYPzD"
        self.chall.save()
        assert (
            self.chall.encoded_token
            == b"QUR3RnhDQVhybms0N3JjQ25uYmJ0R1lTb19sNjFNQ1lYcXRCemlQdDI2bWs3LVF6cFlOTktuVHNLamJCWVB6RA"
        )

    def test_expected(self) -> None:
        """Test the expected property."""
        self.chall.token = "ADwFxCAXrnk47rcCnnbbtGYSo_l61MCYXqtBziPt26mk7-QzpYNNKnTsKjbBYPzD"
        self.chall.save()
        assert self.chall.expected == self.chall.encoded_token + b"." + self.account.thumbprint.encode(
            "utf-8"
        )

        self.chall.type = AcmeChallenge.TYPE_DNS_01
        self.chall.save()
        assert self.chall.expected == b"LoNgngEeuLw4rWDFpplPA0XBp9dd9spzuuqbsRFcKug"

    def test_get_challenge(self) -> None:
        """Test the get_challenge() function."""
        body = self.chall.get_challenge(RequestFactory().get("/"))
        assert isinstance(body, messages.ChallengeBody)
        assert body.chall == self.chall.acme_challenge
        assert body.status == self.chall.status
        assert body.validated == self.chall.acme_validated
        assert body.uri == f"http://testserver{self.chall.acme_url}"

    def test_serial(self) -> None:
        """Test the serial property."""
        assert self.chall.serial == self.chall.auth.order.account.ca.serial


class AcmeCertificateTestCase(TestCaseMixin, AcmeValuesMixin, TestCase):
    """Test :py:class:`django_ca.models.AcmeCertificate`."""

    load_cas = ("root",)

    def setUp(self) -> None:
        super().setUp()
        self.account = AcmeAccount.objects.create(
            ca=self.cas["root"],
            contact="mailto:user@example.com",
            terms_of_service_agreed=True,
            status=AcmeAccount.STATUS_VALID,
            pem=self.ACME_PEM_1,
            thumbprint=self.ACME_THUMBPRINT_1,
        )
        self.order = AcmeOrder.objects.create(account=self.account)
        self.acme_cert = AcmeCertificate.objects.create(order=self.order)

    def test_acme_url(self) -> None:
        """Test the acme_url property."""
        assert self.acme_cert.acme_url == f"/django_ca/acme/{self.order.serial}/cert/{self.acme_cert.slug}/"

    def test_parse_csr(self) -> None:
        """Test the parse_csr property."""
        self.acme_cert.csr = (
            CERT_DATA["root-cert"]["csr"]["parsed"].public_bytes(Encoding.PEM).decode("utf-8")
        )
        assert isinstance(self.acme_cert.parse_csr(), x509.CertificateSigningRequest)
