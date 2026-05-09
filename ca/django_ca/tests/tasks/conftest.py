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

"""Shared fixtures for Celery task tests."""

import shutil
from pathlib import Path

import pytest

from django_ca.models import Certificate, CertificateAuthority
from django_ca.tests.base.constants import FIXTURES_DIR


@pytest.fixture
def make_ocsp_key(tmpcadir: Path, child: CertificateAuthority, profile_ocsp: Certificate) -> None:
    """Configure the *child* CA fixture with a real OCSP responder key so OCSP signing works."""
    shutil.copy(FIXTURES_DIR / "profile-ocsp.key", tmpcadir / "ocsp")
    child.ocsp_key_backend_options = {
        "private_key": {"path": str(tmpcadir / "ocsp")},
        "certificate": {"pem": profile_ocsp.pub.pem},
    }
    child.save()
