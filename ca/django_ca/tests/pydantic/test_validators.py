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

"""Test validators."""

import pytest

from django_ca.pydantic.validators import email_validator


@pytest.mark.parametrize(
    "email,validated",
    [("user@example.com", "user@example.com"), ("user@exämple.com", "user@xn--exmple-cua.com")],
)
def test_validate_email(email: str, validated: str) -> None:
    """Test :py:func:`django_ca.utils.validate_email`."""
    assert email_validator(email) == validated


@pytest.mark.parametrize(
    "email,error",
    [
        ("user@example com", "^Invalid domain: example.com$"),
        ("user", "^Invalid email address: user$"),
        ("example.com", "^Invalid email address: example.com$"),
        ("@example.com", "^@example.com: node part is empty$"),
    ],
)
def test_validate_email_errors(email: str, error: str) -> None:
    """Test errors for :py:func:`django_ca.utils.validate_email`."""
    with pytest.raises(ValueError, match=error):
        email_validator(email)
