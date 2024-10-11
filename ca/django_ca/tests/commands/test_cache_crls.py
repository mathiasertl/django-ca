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

from typing import Optional

from cryptography.hazmat.primitives.serialization import Encoding

from django.core.cache import cache

import pytest

from django_ca.models import Certificate, CertificateAuthority
from django_ca.tests.base.assertions import assert_crl
from django_ca.tests.base.constants import TIMESTAMPS
from django_ca.tests.base.utils import cmd, crl_cache_key, get_idp

# freeze time as otherwise CRLs might have rounding errors
pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"]), pytest.mark.usefixtures("clear_cache")]


def assert_crl_by_ca(ca: CertificateAuthority, expected: Optional[list[Certificate]] = None) -> None:
    """Assert all cached CRLs for the given CA."""
    key = crl_cache_key(ca.serial, only_contains_ca_certs=True)
    crl = cache.get(key)
    assert crl is not None
    idp = get_idp(only_contains_ca_certs=True)
    assert_crl(crl, signer=ca, algorithm=ca.algorithm, encoding=Encoding.DER, idp=idp)

    key = crl_cache_key(ca.serial, only_contains_user_certs=True)
    crl = cache.get(key)
    assert crl is not None
    idp = get_idp(only_contains_user_certs=True)
    assert_crl(crl, signer=ca, algorithm=ca.algorithm, encoding=Encoding.DER, idp=idp, expected=expected)


def test_cmd(usable_cas: list[CertificateAuthority]) -> None:
    """Test the basic command."""
    stdout, stderr = cmd("cache_crls")
    assert stdout == ""
    assert stderr == ""

    for ca in usable_cas:
        assert_crl_by_ca(ca)


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])  # otherwise CRLs might have rounding errors
def test_with_serial(usable_cert: Certificate) -> None:
    """Test passing an explicit serial."""
    usable_cert.revoke()
    ca = usable_cert.ca

    stdout, stderr = cmd("cache_crls", ca.serial)
    assert stdout == ""
    assert stderr == ""
    assert_crl_by_ca(ca, expected=[usable_cert])


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])  # otherwise CRLs might have rounding errors
def test_with_serial_with_empty_crl(usable_ca: CertificateAuthority) -> None:
    """Test passing an explicit serial."""
    stdout, stderr = cmd("cache_crls", usable_ca.serial)
    assert stdout == ""
    assert stderr == ""
    assert_crl_by_ca(usable_ca)
