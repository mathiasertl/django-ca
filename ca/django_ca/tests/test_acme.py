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

"""Test some common ACME functionality."""

import typing
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from typing import Any
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

import pytest

from django_ca.acme import validation
from django_ca.acme.constants import IdentifierType, Status
from django_ca.models import AcmeAccount, AcmeAuthorization, AcmeChallenge, AcmeOrder
from django_ca.tests.base.assertions import assert_count_equal
from django_ca.tests.base.mixins import TestCaseMixin

urlpatterns = [
    path("django_ca/", include("django_ca.urls")),
]


def assert_no_reverse_match(
    name: str, args: typing.Sequence[Any] | None = None, kwargs: dict[str, Any] | None = None
) -> None:
    """Context manager asserting that the given URL pattern is **not** found."""
    urlname = name
    if ":" in urlname:
        _namespace, urlname = name.split(":", 1)

    msg = f"Reverse for '{urlname}' not found. '{urlname}' is not a valid view function or pattern name."
    with pytest.raises(NoReverseMatch, match=msg):
        reverse(name, args=args, kwargs=kwargs)


class TestConstantsTestCase(TestCase):
    """Test constants."""

    def test_status_enum(self) -> None:
        """Test that the Status Enum is equivalent to the main ACME library."""
        expected = [*acme.messages.Status.POSSIBLE_NAMES, "expired"]
        assert_count_equal(expected, [s.value for s in Status])

    def test_identifier_enum(self) -> None:
        """Test that the IdentifierType Enum is equivalent to the main ACME library."""
        actual = list(acme.messages.IdentifierType.POSSIBLE_NAMES)
        assert_count_equal(actual, [s.value for s in IdentifierType])


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
        self, *messages: str, challenge: AcmeChallenge | None = None
    ) -> Iterator[None]:
        """Assert log messages."""
        with self.assertLogs("django_ca.acme.validation", level="DEBUG") as logcm:
            yield

        if challenge is None:
            challenge = self.chall

        assert logcm.output == [self.get_log_message(challenge), *messages]

    def get_log_message(self, chall: AcmeChallenge) -> str:
        """Get the default log message for DNS-01 validation."""
        prefix = "INFO:django_ca.acme.validation"
        domain = chall.auth.value
        expected = chall.expected.decode("utf-8")
        return f"{prefix}:DNS-01 validation of {domain}: Expect {expected} on _acme-challenge.{domain}"

    @contextmanager
    def mock_response(self, domain: str, *responses: Iterable[bytes]) -> Iterator[mock.Mock]:
        """Mock TXT responses for the given domain."""
        dns.resolver.reset_default_resolver()

        txt_responses = [self.to_txt_record(resp) for resp in responses]

        with self.patch_object(dns.resolver.default_resolver, "resolve", autospec=True) as resolve_mock:
            resolve_mock.return_value = txt_responses
            yield resolve_mock

        # Note: Only assert the first two parameters, as otherwise we'd test dnspython internals
        resolve_mock.assert_called_once()
        expected = (f"_acme-challenge.{domain}", "TXT")
        assert resolve_mock.call_args_list[0].args[:2] == expected

    @contextmanager
    def resolve(self, side_effect: Any) -> Iterator[mock.Mock]:
        """Simpler function for mocking top-level resolve function."""
        with mock.patch("dns.resolver.resolve", side_effect=side_effect, autospec=True) as resolve_mock:
            yield resolve_mock

    def to_txt_record(self, values: Iterable[bytes]) -> TXTBase:
        """Convert method to TXT record."""
        return TXTBase(dns.rdataclass.RdataClass.IN, dns.rdatatype.RdataType.TXT, values)

    def test_validation(self) -> None:
        """Test successful DNS-01 validation."""
        with self.mock_response(self.domain, [self.chall.expected]), self.assertLogMessages():
            assert validation.validate_dns_01(self.chall)
        with self.mock_response(self.domain, [self.chall.expected, b"foo"]), self.assertLogMessages():
            assert validation.validate_dns_01(self.chall)
        with self.mock_response(self.domain, [b"data"], [self.chall.expected]), self.assertLogMessages():
            assert validation.validate_dns_01(self.chall)
        with (
            self.mock_response(self.domain, [b"data"], [b"multiple", self.chall.expected]),
            self.assertLogMessages(),
        ):
            assert validation.validate_dns_01(self.chall)

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
            assert validation.validate_dns_01(chall)
        with self.mock_response(self.domain, [expected, b"foo"]), self.assertLogMessages(challenge=chall):
            assert validation.validate_dns_01(chall)
        with self.mock_response(self.domain, [b"data"], [expected]), self.assertLogMessages(challenge=chall):
            assert validation.validate_dns_01(chall)
        with (
            self.mock_response(self.domain, [b"data"], [b"foo", expected]),
            self.assertLogMessages(challenge=chall),
        ):
            assert validation.validate_dns_01(chall)

    def test_wrong_txt_response(self) -> None:
        """Test failing a challenge via the wrong DNS response."""
        with self.mock_response(self.domain, [b"foo"]), self.assertLogMessages():
            assert not validation.validate_dns_01(self.chall)
        with self.mock_response(self.domain, [b"foo"], [b"bar"]), self.assertLogMessages():
            assert not validation.validate_dns_01(self.chall)
        with self.mock_response(self.domain, [b"foo", b"bar"], [b"bar"]), self.assertLogMessages():
            assert not validation.validate_dns_01(self.chall)

    def test_dns_exception(self) -> None:
        """Mock resolver throwing a DNS exception."""
        with self.resolve(side_effect=dns.exception.DNSException) as resolve, self.assertLogs() as logcm:
            assert not validation.validate_dns_01(self.chall)
        resolve.assert_called_once_with(f"_acme-challenge.{self.domain}", "TXT", lifetime=1, search=False)
        assert len(logcm.output) == 2
        assert "dns.exception.DNSException" in logcm.output[1]

    def test_nxdomain(self) -> None:
        """Test validating a domain where the record simply does not exist."""
        with (
            self.resolve(side_effect=resolver.NXDOMAIN) as resolve,
            self.assertLogMessages(
                f"DEBUG:django_ca.acme.validation:TXT _acme-challenge.{self.domain}: record does not exist."
            ),
        ):
            assert not validation.validate_dns_01(self.chall)
        resolve.assert_called_once_with(f"_acme-challenge.{self.domain}", "TXT", lifetime=1, search=False)

    def test_wrong_acme_challenge(self) -> None:
        """Test passing an ACME challenge of the wrong type."""
        with pytest.raises(ValueError, match=r"^This function can only validate DNS-01 challenges$"):
            validation.validate_dns_01(AcmeChallenge(type=AcmeChallenge.TYPE_HTTP_01))

    def test_ip_identifier_rejected(self) -> None:
        """Test that dns-01 raises ValueError for IP identifiers (RFC 8738, section 7)."""
        auth = AcmeAuthorization(value="192.0.2.1", type=AcmeAuthorization.TYPE_IP, order=self.order)
        chall = AcmeChallenge(type=AcmeChallenge.TYPE_DNS_01, auth=auth)
        with pytest.raises(
            ValueError,
            match=r"^dns-01 cannot be used to validate IP identifiers \(RFC 8738, section 7\)$",
        ):
            validation.validate_dns_01(chall)


def test_validate_http_01_wrong_challenge_type() -> None:
    """validate_http_01 raises ValueError when passed a non-HTTP-01 challenge."""
    with pytest.raises(ValueError, match=r"^This function can only validate HTTP-01 challenges$"):
        validation.validate_http_01(AcmeChallenge(type=AcmeChallenge.TYPE_DNS_01))


@pytest.mark.parametrize(
    ("ip_value", "expected_url"),
    (
        ("192.0.2.1", "http://192.0.2.1/.well-known/acme-challenge/testtoken"),
        ("2001:db8::1", "http://[2001:db8::1]/.well-known/acme-challenge/testtoken"),
    ),
)
def test_validate_http_01_ip_url(ip_value: str, expected_url: str) -> None:
    """Test that validate_http_01 builds the correct URL for IP identifiers (RFC 8738, section 5).

    IPv4 addresses are used bare; IPv6 addresses are enclosed in brackets (RFC 3986, section 3.2.2).
    """
    auth = AcmeAuthorization(value=ip_value, type=AcmeAuthorization.TYPE_IP)
    chall = AcmeChallenge(type=AcmeChallenge.TYPE_HTTP_01, auth=auth)

    with (
        mock.patch.object(
            AcmeChallenge, "encoded_token", new_callable=mock.PropertyMock, return_value=b"testtoken"
        ),
        mock.patch.object(
            AcmeChallenge, "expected", new_callable=mock.PropertyMock, return_value=b"testtoken.thumbprint"
        ),
        mock.patch("django_ca.acme.validation.requests.get") as mock_get,
    ):
        mock_get.return_value.__enter__ = mock.Mock(return_value=mock.Mock(status_code=404))
        mock_get.return_value.__exit__ = mock.Mock(return_value=False)
        validation.validate_http_01(chall)

    mock_get.assert_called_once_with(expected_url, timeout=1, stream=True, allow_redirects=False)
