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

"""Test celery message validators."""

import pytest

from django_ca.celery.messages import UseCertificateAuthoritiesTaskArgs


def test_serial_and_exclude() -> None:
    """Test passing a serial and an exclude."""
    with pytest.raises(ValueError, match=r"Message cannot contain both serials and excluded serials\."):
        UseCertificateAuthoritiesTaskArgs(serials=["abc"], exclude=["def"])
