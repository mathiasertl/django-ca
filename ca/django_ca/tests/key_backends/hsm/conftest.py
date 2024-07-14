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

"""Fixtures for HSM testing."""

from collections.abc import Iterator

from pkcs11._pkcs11 import Session

from django.conf import settings

import pytest

from django_ca.key_backends.hsm.session import SessionPool

# pylint: disable=redefined-outer-name  # usefixtures does not work on fixtures.


@pytest.fixture
def session_pool() -> Iterator[None]:
    """Get a clean session pool."""
    # Reinitialize the library, so that any token created before is also visible (SoftHSM only sees token
    # present at initialization time).
    # pylint: disable=use-implicit-booleaness-not-comparison
    # pylint: disable=protected-access  # deliberate access in this entire function
    for lib in SessionPool._lib_pool.values():
        lib.reinitialize()

    # Assert that the session pool *is* clean. Any test leaving sessions intact would show up here.
    assert SessionPool._session_pool == {}
    assert SessionPool._session_refcount == {}

    yield

    # Make sure that we leave no open sessions.
    assert SessionPool._session_pool == {}
    assert SessionPool._session_refcount == {}


@pytest.fixture
def session(softhsm_token: str, session_pool: None) -> Session:  # pylint: disable=unused-argument
    """Fixture providing a fresh (read-only) session."""
    with SessionPool(settings.PKCS11_PATH, softhsm_token, None, settings.PKCS11_USER_PIN) as session:
        yield session
