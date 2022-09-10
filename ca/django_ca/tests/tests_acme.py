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

"""Test some common ACME functionality."""

import sys
import typing
from contextlib import contextmanager
from importlib import reload
from unittest import mock

import acme
import dns.exception
import dns.name
from dns import resolver
from dns.rdtypes.txtbase import TXTBase

from django.test import TestCase
from django.urls import include, path, reverse
from django.urls.exceptions import NoReverseMatch
from django.utils.crypto import get_random_string

from .. import urls
from ..acme import validation
from ..acme.constants import IdentifierType, Status
from ..models import AcmeAccount, AcmeAuthorization, AcmeChallenge, AcmeOrder
from .base import override_settings
from .base.mixins import TestCaseMixin

urlpatterns = [
    path("django_ca/", include("django_ca.urls")),
]


class URLPatternTestCase(TestCase):
    """Test that URL patterns are not enabled when CA_ENABLE_ACME."""

    @contextmanager
    def reload_urlconf(self) -> typing.Iterator[None]:
        """Context manager to reload the current URL configuration."""
        reload(urls)
        try:
            with self.settings(ROOT_URLCONF=__name__):
                yield
        finally:
            reload(urls)

    def assertNoReverseMatch(  # pylint: disable=invalid-name
        self,
        name: str,
        args: typing.Optional[typing.Sequence[typing.Any]] = None,
        kwargs: typing.Optional[typing.Dict[str, typing.Any]] = None,
    ) -> None:
        """Context manager asserting that the given URL pattern is **not** found."""
        urlname = name
        if ":" in name:
            _namespace, urlname = name.split(":", 1)

        msg = f"Reverse for '{urlname}' not found. '{urlname}' is not a valid view function or pattern name."
        with self.assertRaisesRegex(NoReverseMatch, msg):
            reverse(name, args=args, kwargs=kwargs)

    @override_settings(CA_ENABLE_ACME=False)
    def test_disabled(self) -> None:
        """Test that resolving URLs does **NOT** work if disabled."""
        with self.reload_urlconf():
            self.assertNoReverseMatch("django_ca:acme-directory")
            self.assertNoReverseMatch("django_ca:acme-directory", kwargs={"serial": "AB:CD"})
            self.assertNoReverseMatch("django_ca:acme-new-nonce", kwargs={"serial": "AB:CD"})

    def test_enabled(self) -> None:
        """Test that resolving URLs work if enabled."""

        reverse("django_ca:acme-directory")
        reverse("django_ca:acme-directory", kwargs={"serial": "AB:CD"})
        reverse("django_ca:acme-new-nonce", kwargs={"serial": "AB:CD"})


class TestConstantsTestCase(TestCase):
    """Test constants."""

    def test_status_enum(self) -> None:
        """Test that the Status Enum is equivalent to the main ACME library."""

        expected = list(acme.messages.Status.POSSIBLE_NAMES) + ["expired"]
        self.assertCountEqual(expected, [s.value for s in Status])

    def test_identifier_enum(self) -> None:
        """Test that the IdentifierType Enum is equivalent to the main ACME library."""

        actual = list(acme.messages.IdentifierType.POSSIBLE_NAMES)
        if "ip" not in actual:  # pragma: acme<1.19
            actual.append("ip")

        self.assertCountEqual(actual, [s.value for s in IdentifierType])


class Dns01ValidationTestCase(TestCaseMixin, TestCase):
    """Test dns-01 validation."""

    load_cas = ("root", "child")

    def setUp(self) -> None:
        super().setUp()
        self.domain = "example.invalid"
        self.account = AcmeAccount(thumbprint=get_random_string(length=12), ca=self.ca, pem="none")
        urlpath = reverse(
            "django_ca:acme-account", kwargs={"slug": self.account.slug, "serial": self.account.ca.serial}
        )
        self.account.kid = f"http://testserver{urlpath}"
        self.account.save()
        self.order = AcmeOrder.objects.create(account=self.account)
        self.auth = AcmeAuthorization(value=self.domain, order=self.order)
        self.chall = AcmeChallenge(type=AcmeChallenge.TYPE_DNS_01, auth=self.auth)

    @contextmanager
    def assertLogMessages(  # pylint: disable=invalid-name  # unittest standard
        self, *messages: str, challenge: typing.Optional[AcmeChallenge] = None
    ) -> typing.Iterator[None]:
        """Assert log messages."""
        with self.assertLogs("django_ca.acme.validation", level="DEBUG") as logcm:
            yield

        if challenge is None:
            challenge = self.chall

        self.assertEqual(logcm.output, [self.get_log_message(challenge)] + list(messages))

    def get_log_message(self, chall: AcmeChallenge) -> str:
        """Get the default log message for DNS-01 validation."""
        prefix = "INFO:django_ca.acme.validation"
        domain = chall.auth.value
        expected = chall.expected.decode("utf-8")
        return f"{prefix}:DNS-01 validation of {domain}: Expect {expected} on _acme_challenge.{domain}"

    @contextmanager
    def mock_response(self, domain: str, *responses: typing.Iterable[bytes]) -> typing.Iterator[mock.Mock]:
        """Mock TXT responses for the given domain."""
        dns.resolver.reset_default_resolver()
        txt_responses = [self.to_txt_record(resp) for resp in responses]

        with mock.patch.object(dns.resolver.default_resolver, "resolve", autospec=True) as resolve_mock:
            resolve_mock.return_value = txt_responses
            yield resolve_mock

        # Note: Only assert the first two parameters, as otherwise we'd test dnspython internals
        resolve_mock.assert_called_once()
        expected = (f"_acme_challenge.{domain}", "TXT")
        if sys.version_info[0:2] < (3, 8):  # pragma: only py<3.8
            args, kwargs = list(resolve_mock.call_args_list[0])
            self.assertEqual(args[:2], expected)
        else:
            self.assertEqual(resolve_mock.call_args_list[0].args[:2], expected)

    @contextmanager
    def resolve(self, side_effect: typing.Any) -> typing.Iterator[mock.Mock]:
        """Simpler function for mocking top-level resolve function."""
        with mock.patch("dns.resolver.resolve", side_effect=side_effect, autospec=True) as resolve_mock:
            yield resolve_mock

    def to_txt_record(self, values: typing.Iterable[bytes]) -> TXTBase:
        """Convert method to TXT record."""
        return TXTBase(dns.rdataclass.RdataClass.IN, dns.rdatatype.RdataType.TXT, values)

    def test_validation(self) -> None:
        """Test successful DNS-01 validation."""
        with self.mock_response(self.domain, [self.chall.expected]), self.assertLogMessages():
            self.assertTrue(validation.validate_dns_01(self.chall))
        with self.mock_response(self.domain, [self.chall.expected, b"foo"]), self.assertLogMessages():
            self.assertTrue(validation.validate_dns_01(self.chall))
        with self.mock_response(self.domain, [b"data"], [self.chall.expected]), self.assertLogMessages():
            self.assertTrue(validation.validate_dns_01(self.chall))
        with self.mock_response(
            self.domain, [b"data"], [b"multiple", self.chall.expected]
        ), self.assertLogMessages():
            self.assertTrue(validation.validate_dns_01(self.chall))

    def test_precomputed(self) -> None:
        """Runa test with pre-computed values to test basic behavior."""
        account = AcmeAccount(thumbprint="R6tWUSaH6DQH", ca=self.ca, pem="test_precomputed")
        urlpath = reverse(
            "django_ca:acme-account", kwargs={"slug": account.slug, "serial": account.ca.serial}
        )
        account.kid = f"http://testserver{urlpath}"
        account.save()
        order = AcmeOrder.objects.create(account=account)
        auth = AcmeAuthorization(value=self.domain, order=order)
        chall = AcmeChallenge(type=AcmeChallenge.TYPE_DNS_01, auth=auth, token="5I4xiP4z29Mu")
        expected = chall.expected

        with self.mock_response(self.domain, [chall.expected]), self.assertLogMessages(challenge=chall):
            self.assertTrue(validation.validate_dns_01(chall))
        with self.mock_response(self.domain, [expected, b"foo"]), self.assertLogMessages(challenge=chall):
            self.assertTrue(validation.validate_dns_01(chall))
        with self.mock_response(self.domain, [b"data"], [expected]), self.assertLogMessages(challenge=chall):
            self.assertTrue(validation.validate_dns_01(chall))
        with self.mock_response(self.domain, [b"data"], [b"foo", expected]), self.assertLogMessages(
            challenge=chall
        ):
            self.assertTrue(validation.validate_dns_01(chall))

    def test_wrong_txt_response(self) -> None:
        """Test failing a challenge via the wrong DNS response."""
        with self.mock_response(self.domain, [b"foo"]), self.assertLogMessages():
            self.assertFalse(validation.validate_dns_01(self.chall))
        with self.mock_response(self.domain, [b"foo"], [b"bar"]), self.assertLogMessages():
            self.assertFalse(validation.validate_dns_01(self.chall))
        with self.mock_response(self.domain, [b"foo", b"bar"], [b"bar"]), self.assertLogMessages():
            self.assertFalse(validation.validate_dns_01(self.chall))

    def test_dns_exception(self) -> None:
        """Mock resolver throwing a DNS exception."""
        with self.resolve(side_effect=dns.exception.DNSException) as resolve, self.assertLogs() as logcm:
            self.assertFalse(validation.validate_dns_01(self.chall))
        resolve.assert_called_once_with(f"_acme_challenge.{self.domain}", "TXT", lifetime=1, search=False)
        self.assertEqual(len(logcm.output), 2)
        self.assertIn("dns.exception.DNSException", logcm.output[1])

    def test_nxdomain(self) -> None:
        """Test validating a domain where the record simply does not exist."""

        with self.resolve(side_effect=resolver.NXDOMAIN) as resolve, self.assertLogMessages(
            f"DEBUG:django_ca.acme.validation:TXT _acme_challenge.{self.domain}: record does not exist."
        ):
            self.assertFalse(validation.validate_dns_01(self.chall))
        resolve.assert_called_once_with(f"_acme_challenge.{self.domain}", "TXT", lifetime=1, search=False)

    def test_wrong_acme_challenge(self) -> None:
        """Test passing an ACME challenge of the wrong type."""
        with self.assertRaisesRegex(ValueError, r"^This function can only validate DNS-01 challenges$"):
            validation.validate_dns_01(AcmeChallenge(type=AcmeChallenge.TYPE_HTTP_01))
        with self.assertRaisesRegex(ValueError, r"^This function can only validate DNS-01 challenges$"):
            validation.validate_dns_01(AcmeChallenge(type=AcmeChallenge.TYPE_TLS_ALPN_01))
