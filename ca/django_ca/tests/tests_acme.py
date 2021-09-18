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
from django.urls import include
from django.urls import path
from django.urls import reverse
from django.urls.exceptions import NoReverseMatch

from .. import urls
from ..acme import validation
from ..acme.constants import IdentifierType
from ..acme.constants import Status
from ..models import AcmeAccount
from ..models import AcmeAuthorization
from ..models import AcmeChallenge
from ..models import AcmeOrder
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

    load_cas = ["root", "child"]

    def setUp(self):
        super().setUp()
        self.domain = "example.invalid"
        self.account = AcmeAccount.objects.create(thumbprint="test-thumbprint", ca=self.ca)
        self.order = AcmeOrder.objects.create(account=self.account)
        self.auth = AcmeAuthorization(value=self.domain, order=self.order)
        self.chall = AcmeChallenge(type=AcmeChallenge.TYPE_DNS_01, auth=self.auth)

    @contextmanager
    def mock_response(self, domain, *records):
        dns.resolver.reset_default_resolver()
        responses = [
            TXTBase(dns.rdataclass.RdataClass.IN, dns.rdatatype.RdataType.TXT, rec) for rec in records
        ]
        with mock.patch.object(dns.resolver.default_resolver, "resolve", autospec=True) as rm:
            rm.return_value = responses
            yield rm

        # Note: Only assert the first two parameters, as otherwise we'd test dnspython internals
        rm.assert_called_once()
        self.assertEqual(rm.call_args_list[0].args[:2], (f"_acme_challenge.{domain}", "TXT"))

    def test_wrong_txt_response(self):
        with self.mock_response(self.domain, "foo"):
            self.assertFalse(validation.validate_dns_01(self.chall))
        with self.mock_response(self.domain, "foo", "bar"):
            self.assertFalse(validation.validate_dns_01(self.chall))

    def test_dns_exception(self):
        with mock.patch("dns.resolver.resolve", side_effect=dns.exception.DNSException) as rm:
            self.assertFalse(validation.validate_dns_01(self.chall))
        rm.assert_called_once_with(f"_acme_challenge.{self.domain}", "TXT", lifetime=1, search=False)

    def test_nxdomain(self):
        """Test validating a domain where the record simply does not exist."""

        with mock.patch("dns.resolver.resolve", side_effect=resolver.NXDOMAIN) as rm, self.assertLogs(
            "django_ca.acme.validation", level="DEBUG"
        ) as logcm:
            self.assertFalse(validation.validate_dns_01(self.chall))

        self.assertEqual(
            logcm.output,
            [
                f"INFO:django_ca.acme.validation:DNS-01 validation of {self.domain}",
                f"DEBUG:django_ca.acme.validation:TXT _acme_challenge.{self.domain}: record does not exist.",
            ],
        )
        rm.assert_called_once_with(f"_acme_challenge.{self.domain}", "TXT", lifetime=1, search=False)

    def test_wrong_acme_challenge(self):
        """Test passing an ACME challenge of the wrong type."""
        with self.assertRaisesRegex(ValueError, r"^This function can only validate DNS-01 challenges$"):
            validation.validate_dns_01(AcmeChallenge(type=AcmeChallenge.TYPE_HTTP_01))
        with self.assertRaisesRegex(ValueError, r"^This function can only validate DNS-01 challenges$"):
            validation.validate_dns_01(AcmeChallenge(type=AcmeChallenge.TYPE_TLS_ALPN_01))

    def test_no_dnspython(self):
        with mock.patch("django_ca.acme.validation.resolver", None), self.assertLogs() as logcm:
            validation.validate_dns_01("Foo")

        self.assertEqual(
            logcm.output,
            ["ERROR:django_ca.acme.validation:Cannot validate DNS-01 challenge: dnspython is not installed"],
        )
