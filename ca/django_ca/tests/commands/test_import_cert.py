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

"""Test the import_cert  management command."""

from typing import Any

import pytest

from django_ca.models import Certificate, CertificateAuthority
from django_ca.tests.base.assertions import assert_command_error, assert_signature
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS
from django_ca.tests.base.utils import cmd


def import_cert(name: str, **kwargs: Any) -> Certificate:
    """Execute the import_cert command."""
    cert_path = CERT_DATA[name]["pub_path"]
    out, err = cmd("import_cert", cert_path, **kwargs)
    assert out == ""
    assert err == ""
    return Certificate.objects.get(serial=CERT_DATA["root-cert"]["serial"])


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
def test_basic(root: CertificateAuthority) -> None:
    """Import a standard certificate."""
    cert = import_cert("root-cert", ca=root)
    assert_signature([root], cert)
    assert cert.ca, root
    cert.full_clean()  # assert e.g. max_length in serials


def test_bogus(root: CertificateAuthority) -> None:
    """Try to import bogus data."""
    with assert_command_error(r"^Unable to load public key\.$"):
        cmd("import_cert", __file__, ca=root)
    assert Certificate.objects.count() == 0
