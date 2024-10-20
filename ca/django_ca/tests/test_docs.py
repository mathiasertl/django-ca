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

# pylint: disable=redefined-outer-name  # requested pytest fixtures show up this way.

"""Test some Sphinx documentation."""

import doctest
import os
from typing import Any

from cryptography import x509

import pytest

from django_ca.models import Certificate, CertificateAuthority
from django_ca.tests.base.constants import CERT_DATA, DOC_DIR

BASE = os.path.relpath(DOC_DIR, os.path.dirname(__file__))


@pytest.fixture
def globs(usable_root: CertificateAuthority, root_cert: Certificate) -> dict[str, Any]:
    """Fixture for global variables available to doctests."""
    return {
        "ca": usable_root,
        "ca_serial": usable_root.serial,
        "cert": root_cert,
        "cert_serial": root_cert.serial,
        "csr": CERT_DATA["root-cert"]["csr"]["parsed"],
        "x509": x509,
    }


def test_python_intro(globs: dict[str, Any]) -> None:
    """Test python/intro.rst."""
    failures, _tests = doctest.testfile(os.path.join(BASE, "python", "intro.rst"), globs=globs)
    assert failures == 0, f"{failures} doctests failed, see above for output."


def test_python_models(globs: dict[str, Any]) -> None:
    """Test python/models.rst."""
    failures, _tests = doctest.testfile(os.path.join(BASE, "python", "models.rst"), globs=globs)
    assert failures == 0, f"{failures} doctests failed, see above for output."


def test_python_pydantic_models(globs: dict[str, Any]) -> None:
    """Test python/models.rst."""
    failures, _tests = doctest.testfile(os.path.join(BASE, "python", "pydantic.rst"), globs=globs)
    assert failures == 0, f"{failures} doctests failed, see above for output."
