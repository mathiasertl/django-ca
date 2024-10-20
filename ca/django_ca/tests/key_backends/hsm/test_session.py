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


"""Test HSM related code."""

import subprocess
from collections.abc import Iterator
from typing import Optional

from pkcs11._pkcs11 import Session

from django.conf import settings
from django.utils.crypto import get_random_string

import pytest

from django_ca.key_backends.hsm.session import SessionPool

PoolKeyType = tuple[str, str, Optional[str], Optional[str]]

# pylint: disable=redefined-outer-name  # several fixtures are defined here
# pylint: disable=protected-access  # we test class internals throughout this module


@pytest.fixture
def pool_key(softhsm_token: str) -> Iterator[PoolKeyType]:
    """Minor fixture to return the pool key for the default settings."""
    return settings.PKCS11_PATH, softhsm_token, None, settings.PKCS11_USER_PIN


@pytest.fixture
def second_softhsm_token(softhsm_token: str) -> Iterator[str]:  # pylint: disable=unused-argument
    """Fixture to create a second softhsm token."""
    label = f"pytest.{get_random_string(8)}.dual"

    so_pin = settings.PKCS11_SO_PIN
    pin = settings.PKCS11_USER_PIN

    subprocess.run(
        ["softhsm2-util", "--init-token", "--free", "--label", label, "--so-pin", so_pin, "--pin", pin],
        check=True,
    )

    yield label

    subprocess.run(["softhsm2-util", "--delete-token", "--token", label], check=True)


def test_duplicate_session(softhsm_token: str, session: Session, pool_key: PoolKeyType) -> None:
    """Test that a second session request does not open a new session."""
    assert isinstance(session, Session)
    assert SessionPool._session_pool == {pool_key: session}
    assert SessionPool._session_refcount == {pool_key: 1}

    # Get another session, even though it's in the same thread, refcount still goes up
    with SessionPool(settings.PKCS11_PATH, softhsm_token, None, settings.PKCS11_USER_PIN) as second_session:
        assert session is second_session
        assert isinstance(second_session, Session)
        assert SessionPool._session_pool == {pool_key: session}
        assert SessionPool._session_refcount == {pool_key: 2}

    # Test that second session was cleaned up
    assert SessionPool._session_pool == {pool_key: session}
    assert SessionPool._session_refcount == {pool_key: 1}


def test_duplicate_rw_session(softhsm_token: str, session: Session, pool_key: PoolKeyType) -> None:
    """Test that requesting a read/write session when it is already open read-only is an error."""
    assert SessionPool._session_pool == {pool_key: session}
    assert SessionPool._session_refcount == {pool_key: 1}
    with pytest.raises(
        ValueError, match=r"^Requested R/W session, but R/O session is already initialized\.$"
    ):
        with SessionPool(settings.PKCS11_PATH, softhsm_token, None, settings.PKCS11_USER_PIN, rw=True):
            pass

    # Test that the ref count has not increased
    assert SessionPool._session_pool == {pool_key: session}
    assert SessionPool._session_refcount == {pool_key: 1}


def test_two_sessions(second_softhsm_token: str, session: Session, pool_key: PoolKeyType) -> None:
    """Test creating a second token with dual sessions."""
    # assert that we have one session in the beginning
    assert SessionPool._session_pool == {pool_key: session}
    assert SessionPool._session_refcount == {pool_key: 1}

    pin = settings.PKCS11_USER_PIN
    second_pool_key = (settings.PKCS11_PATH, second_softhsm_token, None, pin)

    # Create a second session and observe dual session pool
    with SessionPool(settings.PKCS11_PATH, second_softhsm_token, None, pin) as second_session:
        assert SessionPool._session_pool == {pool_key: session, second_pool_key: second_session}
        assert SessionPool._session_refcount == {pool_key: 1, second_pool_key: 1}

        # Try to get a nested session...
        with SessionPool(settings.PKCS11_PATH, second_softhsm_token, None, pin) as third_session:
            assert second_session is third_session
            assert SessionPool._session_pool == {pool_key: session, second_pool_key: second_session}
            assert SessionPool._session_refcount == {pool_key: 1, second_pool_key: 2}

    # session was cleared from pool
    assert SessionPool._session_pool == {pool_key: session}
    assert SessionPool._session_refcount == {pool_key: 1}


def test_both_pins_empty() -> None:
    """Test error when both so_pin and user_pin are not set."""
    with pytest.raises(ValueError, match=r"^so_pin and user_pin cannot both be None\.$"):
        with SessionPool(settings.PKCS11_PATH, "any", None, None):
            pass


def test_both_pins_set() -> None:
    """Test error when both so_pin and user_pin are not set."""
    with pytest.raises(ValueError, match=r"^Either so_pin and user_pin must be set\.$"):
        with SessionPool(settings.PKCS11_PATH, "any", "foo", "bar"):
            pass
