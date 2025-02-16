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

import pytest
from _pytest.logging import LogCaptureFixture

from django_ca.key_backends.hsm import HSMBackend
from django_ca.key_backends.hsm.models import (
    HSMCreatePrivateKeyOptions,
    HSMUsePrivateKeyOptions,
)


@pytest.mark.parametrize(("so_pin", "user_pin"), (("so-pin-value", None), (None, "user-pin-value")))
def test_pins(so_pin: str | None, user_pin: str | None) -> None:
    """Test valid pin configurations."""
    model = HSMUsePrivateKeyOptions(so_pin=so_pin, user_pin=user_pin)
    assert model.so_pin == so_pin
    assert model.user_pin == user_pin


@pytest.mark.parametrize(
    ("so_pin", "user_pin", "error"),
    (
        (None, None, r"Provide one of so_pin or user_pin\."),
        ("so-pin-value", "user-pin-value", r"Provide either so_pin or user_pin\."),
    ),
)
def test_invalid_pins(so_pin: str | None, user_pin: str | None, error: str) -> None:
    """Test invalid pin configurations."""
    with pytest.raises(ValueError, match=error):
        HSMUsePrivateKeyOptions(so_pin=so_pin, user_pin=user_pin)


def test_with_elliptic_curve_with_rsa_key() -> None:
    """Test creating a model with an elliptic curve with a key type that doesn't support it."""
    with pytest.raises(ValueError, match=r"Elliptic curves are not supported for RSA keys."):
        HSMCreatePrivateKeyOptions(
            key_label="foo", user_pin="123", key_type="RSA", elliptic_curve="sect571r1"
        )


def test_with_hsm_backend(hsm_backend: HSMBackend) -> None:
    """Test creating a Model with loading the pins from the context."""
    model = HSMUsePrivateKeyOptions.model_validate({}, context={"backend": hsm_backend}, strict=True)
    assert model.user_pin is not None
    assert model.user_pin == hsm_backend.user_pin
    assert model.so_pin is None


def test_with_hsm_backend_with_pins(hsm_backend: HSMBackend) -> None:
    """Test creating a model instance with context when the pin is already set."""
    model = HSMUsePrivateKeyOptions.model_validate({"user_pin": "dict"}, context={"backend": hsm_backend})
    assert model.user_pin == "dict"  # backend does not overwrite this
    assert model.so_pin is None


def test_with_no_context(caplog: LogCaptureFixture) -> None:
    """Test creating a Model with loading the pins from the context."""
    model = HSMUsePrivateKeyOptions.model_validate({"user_pin": "dict"})
    assert model.user_pin == "dict"
    assert model.so_pin is None
    assert "No context passed." in caplog.text


def test_with_no_backend_in_context(caplog: LogCaptureFixture) -> None:
    """Test creating a Model with loading the pins from the context."""
    with pytest.raises(ValueError):  # noqa: PT011  # pydantic controls the message
        HSMUsePrivateKeyOptions.model_validate({}, context={"foo": "bar"})
    assert "Did not receive backend in context." in caplog.text
