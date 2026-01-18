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

"""Test the generate_crls management command."""

import pytest

from django_ca.models import Certificate, CertificateAuthority, CertificateRevocationList
from django_ca.tests.base.assertions import assert_command_error, assert_crls
from django_ca.tests.base.constants import TIMESTAMPS
from django_ca.tests.base.utils import cmd

# freeze time as otherwise CRLs might have rounding errors
pytestmark = [
    pytest.mark.freeze_time(TIMESTAMPS["everything_valid"]),
    pytest.mark.usefixtures("db", "clear_cache"),
]


def test_cmd(usable_cas: list[CertificateAuthority]) -> None:
    """Test the basic command."""
    stdout, stderr = cmd("generate_crls")
    assert stdout == ""
    assert stderr == ""

    for ca in usable_cas:
        assert_crls(ca)


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])  # otherwise CRLs might have rounding errors
def test_with_serial(usable_cert: Certificate) -> None:
    """Test passing an explicit serial."""
    usable_cert.revoke()

    stdout, stderr = cmd("generate_crls", usable_cert.ca.serial)
    assert stdout == ""
    assert stderr == ""
    assert_crls(usable_cert.ca, expected_user=[usable_cert])


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])  # otherwise CRLs might have rounding errors
def test_with_exclude(usable_root: CertificateAuthority, usable_ec: CertificateAuthority) -> None:
    """Test passing an explicit serial."""
    stdout, stderr = cmd("generate_crls", exclude=[usable_ec.serial])
    assert stdout == ""
    assert stderr == ""
    assert_crls(usable_root)
    assert CertificateRevocationList.objects.filter(ca=usable_ec).exists() is False


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])  # otherwise CRLs might have rounding errors
def test_with_force(usable_root: CertificateAuthority) -> None:
    """Test passing an explicit serial."""
    stdout, stderr = cmd("generate_crls")
    assert stdout == ""
    assert stderr == ""
    assert_crls(usable_root)

    stdout, stderr = cmd("generate_crls", force=True)
    assert stdout == ""
    assert stderr == ""
    assert_crls(usable_root, number=1)


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])  # otherwise CRLs might have rounding errors
def test_with_serial_with_empty_crl(usable_ca: CertificateAuthority) -> None:
    """Test passing an explicit serial."""
    stdout, stderr = cmd("generate_crls", usable_ca.serial)
    assert stdout == ""
    assert stderr == ""
    assert_crls(usable_ca)


def test_deprecated_cmd_name(usable_root: CertificateAuthority) -> None:
    """Test the deprecated command name."""
    stdout, stderr = cmd("cache_crls")
    assert stdout == ""
    assert (
        stderr == "Warning: This command is deprecated. Please use generate_crls instead. "
        "This alias will be removed in django_ca~=3.2.0.\n"
    )
    assert_crls(usable_root)


def test_with_serial_and_exclude() -> None:
    """Test passing both an explicit serial and an exclusion (makes no sense)."""
    with assert_command_error(r"^Cannot name serials and exclude list at the same time\.$"):
        cmd("generate_crls", serials=["abc"], exclude=["def"])
