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

"""Test the cache_crls management command."""

from typing import List, Optional

from cryptography.hazmat.primitives.serialization import Encoding

from django.core.cache import cache
from django.urls import reverse

import pytest
from pytest_django.fixtures import SettingsWrapper

from django_ca.models import Certificate, CertificateAuthority
from django_ca.tests.base.assertions import assert_crl
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS
from django_ca.tests.base.utils import cmd, get_idp, idp_full_name, uri
from django_ca.utils import get_crl_cache_key

# freeze time as otherwise CRLs might have rounding errors
pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])]


def assert_crl_by_ca(ca: CertificateAuthority, expected: Optional[List[Certificate]] = None) -> None:
    """Assert all cached CRLs for the given CA."""
    key = get_crl_cache_key(ca.serial, Encoding.DER, "ca")
    crl = cache.get(key)
    assert crl is not None
    if ca.parent:
        url_path = reverse("django_ca:ca-crl", kwargs={"serial": ca.serial})
        idp = get_idp(full_name=[uri(f"http://localhost:8000{url_path}")], only_contains_ca_certs=True)
    else:
        idp = get_idp(only_contains_ca_certs=True)

    assert_crl(crl, signer=ca, algorithm=ca.algorithm, encoding=Encoding.DER, idp=idp)

    key = get_crl_cache_key(ca.serial, Encoding.DER, "user")
    crl = cache.get(key)
    assert crl is not None
    idp = get_idp(full_name=idp_full_name(ca), only_contains_user_certs=True)
    assert_crl(crl, signer=ca, algorithm=ca.algorithm, encoding=Encoding.DER, idp=idp, expected=expected)


def test_cmd(settings: SettingsWrapper, usable_cas: List[CertificateAuthority]) -> None:
    """Test the basic command."""
    settings.CA_CRL_PROFILES = {
        "user": {
            "expires": 86400,
            "scope": "user",
            "encodings": ["PEM", "DER"],
            "OVERRIDES": {
                CERT_DATA["pwd"]["serial"]: {"skip": True},
            },
        },
        "ca": {
            "expires": 86400,
            "scope": "ca",
            "encodings": ["PEM", "DER"],
            "OVERRIDES": {
                CERT_DATA["pwd"]["serial"]: {"skip": True},
            },
        },
    }

    stdout, stderr = cmd("cache_crls")
    assert stdout == ""
    assert stderr == ""

    for ca in usable_cas:
        if ca.name == "pwd":
            # TODO: not supported yet
            continue
        assert_crl_by_ca(ca)


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])  # otherwise CRLs might have rounding errors
def test_with_serial(usable_cert: Certificate) -> None:
    """Test passing an explicit serial."""
    usable_cert.revoke()
    ca = usable_cert.ca
    if CERT_DATA[ca.name].get("password"):
        # TODO: not yet possible
        return

    stdout, stderr = cmd("cache_crls", ca.serial)
    assert stdout == ""
    assert stderr == ""
    assert_crl_by_ca(ca, expected=[usable_cert])


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])  # otherwise CRLs might have rounding errors
def test_with_serial_with_empty_crl(usable_ca: CertificateAuthority) -> None:
    """Test passing an explicit serial."""
    if CERT_DATA[usable_ca.name].get("password"):
        # TODO: not yet possible
        return

    stdout, stderr = cmd("cache_crls", usable_ca.serial)
    assert stdout == ""
    assert stderr == ""
    assert_crl_by_ca(usable_ca)
