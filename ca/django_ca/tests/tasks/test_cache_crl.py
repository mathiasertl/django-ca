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

"""Test the cache_crl task."""

import pytest

from django_ca.models import CertificateAuthority
from django_ca.tasks import cache_crl
from django_ca.tests.tasks.conftest import assert_crls

pytestmark = [pytest.mark.usefixtures("clear_cache")]


def test_basic(usable_root: CertificateAuthority) -> None:
    """Test the most basic invocation."""
    cache_crl(usable_root.serial)
    assert_crls(usable_root)
