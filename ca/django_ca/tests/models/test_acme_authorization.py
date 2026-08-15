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

"""Tests for :py:class:`django_ca.models.AcmeAuthorization`."""

# pylint: disable=redefined-outer-name  # requested pytest fixtures show up this way.

import ipaddress

from acme import messages

from cryptography import x509

import pytest

from django_ca.models import AcmeAccount, AcmeAuthorization, AcmeChallenge, AcmeOrder, CertificateAuthority

pytestmark = pytest.mark.django_db


@pytest.fixture
def auth(acme_order: AcmeOrder) -> AcmeAuthorization:
    """A DNS authorization for example.com."""
    return AcmeAuthorization.objects.create(
        order=acme_order, type=AcmeAuthorization.TYPE_DNS, value="example.com"
    )


@pytest.fixture
def auth2(acme_order: AcmeOrder) -> AcmeAuthorization:
    """A second DNS authorization for example.net."""
    return AcmeAuthorization.objects.create(
        order=acme_order, type=AcmeAuthorization.TYPE_DNS, value="example.net"
    )


@pytest.fixture
def auth_ipv4(acme_order: AcmeOrder) -> AcmeAuthorization:
    """An IP authorization for an IPv4 address."""
    return AcmeAuthorization.objects.create(
        order=acme_order, type=AcmeAuthorization.TYPE_IP, value="192.0.2.1"
    )


@pytest.fixture
def auth_ipv6(acme_order: AcmeOrder) -> AcmeAuthorization:
    """An IP authorization for an IPv6 address."""
    return AcmeAuthorization.objects.create(
        order=acme_order, type=AcmeAuthorization.TYPE_IP, value="2001:db8::1"
    )


def test_str(auth: AcmeAuthorization, auth2: AcmeAuthorization) -> None:
    """Test the __str__ method."""
    assert str(auth) == "dns: example.com"
    assert str(auth2) == "dns: example.net"


def test_account_property(
    auth: AcmeAuthorization, auth2: AcmeAuthorization, acme_account: AcmeAccount
) -> None:
    """Test the account property."""
    assert auth.account == acme_account
    assert auth2.account == acme_account


def test_acme_url(auth: AcmeAuthorization, auth2: AcmeAuthorization, root: CertificateAuthority) -> None:
    """Test acme_url property."""
    assert auth.acme_url == f"/django_ca/acme/{root.serial}/authz/{auth.slug}/"
    assert auth2.acme_url == f"/django_ca/acme/{root.serial}/authz/{auth2.slug}/"


def test_expires(auth: AcmeAuthorization, auth2: AcmeAuthorization, acme_order: AcmeOrder) -> None:
    """Test the expires property."""
    assert auth.expires == acme_order.expires
    assert auth2.expires == acme_order.expires


def test_identifier(auth: AcmeAuthorization, auth2: AcmeAuthorization) -> None:
    """Test the identifier property for DNS authorizations."""
    assert auth.identifier == messages.Identifier(typ=messages.IDENTIFIER_FQDN, value="example.com")
    assert auth2.identifier == messages.Identifier(typ=messages.IDENTIFIER_FQDN, value="example.net")


def test_identifier_ip(auth_ipv4: AcmeAuthorization, auth_ipv6: AcmeAuthorization) -> None:
    """Test the identifier property for IP authorizations (RFC 8738)."""
    assert auth_ipv4.identifier == messages.Identifier(typ=messages.IDENTIFIER_IP, value="192.0.2.1")
    assert auth_ipv6.identifier == messages.Identifier(typ=messages.IDENTIFIER_IP, value="2001:db8::1")


def test_identifier_unknown_type(auth: AcmeAuthorization) -> None:
    """Test that an identifier with an unknown type raises a ValueError."""
    auth.type = "foo"
    with pytest.raises(ValueError, match=r"^Unknown identifier type: foo$"):
        auth.identifier  # noqa: B018


def test_general_name(auth: AcmeAuthorization, auth2: AcmeAuthorization) -> None:
    """Test the general_name property for DNS authorizations."""
    assert auth.general_name == x509.DNSName("example.com")
    assert auth2.general_name == x509.DNSName("example.net")


def test_general_name_ip(auth_ipv4: AcmeAuthorization, auth_ipv6: AcmeAuthorization) -> None:
    """Test the general_name property for IP authorizations (RFC 8738)."""
    assert auth_ipv4.general_name == x509.IPAddress(ipaddress.ip_address("192.0.2.1"))
    assert auth_ipv6.general_name == x509.IPAddress(ipaddress.ip_address("2001:db8::1"))


def test_general_name_unknown_type(auth: AcmeAuthorization) -> None:
    """Test that general_name raises ValueError for an unknown type."""
    auth.type = "foo"
    with pytest.raises(ValueError, match=r"^foo: Unsupported type\.$"):
        auth.general_name  # noqa: B018


def test_subject_alternative_name(auth: AcmeAuthorization, auth2: AcmeAuthorization) -> None:
    """Test the subject_alternative_name property for DNS authorizations."""
    assert auth.subject_alternative_name == "dns:example.com"
    assert auth2.subject_alternative_name == "dns:example.net"


def test_subject_alternative_name_ip(auth_ipv4: AcmeAuthorization, auth_ipv6: AcmeAuthorization) -> None:
    """Test the subject_alternative_name property for IP authorizations (RFC 8738)."""
    assert auth_ipv4.subject_alternative_name == "ip:192.0.2.1"
    assert auth_ipv6.subject_alternative_name == "ip:2001:db8::1"


def test_get_challenges(auth: AcmeAuthorization) -> None:
    """Test the get_challenges() method for DNS authorizations."""
    challenges = auth.get_challenges()
    assert len(challenges) == 2
    assert challenges[0].type == AcmeChallenge.TYPE_HTTP_01
    assert challenges[1].type == AcmeChallenge.TYPE_DNS_01

    # Calling again must not create duplicates.
    assert auth.get_challenges() == challenges
    assert AcmeChallenge.objects.filter(auth=auth).count() == 2


def test_get_challenges_ip(auth_ipv4: AcmeAuthorization) -> None:
    """Test that get_challenges() omits dns-01 for IP authorizations (RFC 8738, section 7)."""
    challenges = auth_ipv4.get_challenges()
    assert len(challenges) == 1
    assert challenges[0].type == AcmeChallenge.TYPE_HTTP_01

    # Calling again must not create duplicates.
    assert auth_ipv4.get_challenges() == challenges
    assert AcmeChallenge.objects.filter(auth=auth_ipv4).count() == 1
