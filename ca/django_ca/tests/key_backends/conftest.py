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

"""Test fixtures for testing key backends."""

from collections.abc import Iterator

import pytest

from django_ca.key_backends import key_backends
from django_ca.key_backends.base import KeyBackends


@pytest.fixture
def clean_key_backends() -> Iterator[KeyBackends]:
    """Fixture to make sure that no key backends are loaded yet."""
    key_backends._reset()  # pylint: disable=protected-access
    yield key_backends
    key_backends._reset()  # pylint: disable=protected-access
