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

"""Tests for models used in the HSM key backend."""

from typing import Optional

import pytest

from django_ca.key_backends.hsm.models import (
    HSMCreatePrivateKeyOptions,
    HSMUsePrivateKeyOptions,
)


@pytest.mark.parametrize("so_pin,user_pin", (("so-pin-value", None), (None, "user-pin-value")))
def test_pins(so_pin: Optional[str], user_pin: Optional[str]) -> None:
    """Test valid pin configurations."""
    model = HSMUsePrivateKeyOptions(so_pin=so_pin, user_pin=user_pin)
    assert model.so_pin == so_pin
    assert model.user_pin == user_pin


@pytest.mark.parametrize(
    "so_pin,user_pin,error",
    (
        (None, None, r"Provide one of so_pin or user_pin\."),
        ("so-pin-value", "user-pin-value", r"Provide either so_pin or user_pin\."),
    ),
)
def test_invalid_pins(so_pin: Optional[str], user_pin: Optional[str], error: str) -> None:
    """Test invalid pin configurations."""
    with pytest.raises(ValueError, match=error):
        HSMUsePrivateKeyOptions(so_pin=so_pin, user_pin=user_pin)


def test_with_elliptic_curve_with_rsa_key() -> None:
    """Test creating a model with an elliptic curve with a key type that doesn't support it."""
    with pytest.raises(ValueError, match=r"Elliptic curves are not supported for RSA keys."):
        HSMCreatePrivateKeyOptions(
            key_label="foo", user_pin="123", key_type="RSA", elliptic_curve="sect571r1"
        )
