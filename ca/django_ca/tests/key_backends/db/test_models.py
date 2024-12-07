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

"""Test models of the db backend."""

import pytest

from django_ca.key_backends.db.models import DBCreatePrivateKeyOptions


def test_create_with_elliptic_curve_with_no_ec_key() -> None:
    """Test creating a private key options object with an EC curve and no EC key."""
    with pytest.raises(ValueError):  # noqa: PT011
        DBCreatePrivateKeyOptions(key_type="RSA", elliptic_curve="sect233r1")
