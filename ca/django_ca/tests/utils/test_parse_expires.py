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

"""Test :py:func:`~django_ca.utils.parse_expires`."""

from datetime import datetime, timedelta, timezone as tz

import pytest

from django_ca.conf import model_settings
from django_ca.utils import parse_expires

pytestmark = [pytest.mark.freeze_time("2023-04-30 12:30:50.12")]


def test_no_args() -> None:
    """Test invocation with no args."""
    assert parse_expires() == datetime(2023, 4, 30, 12, 30, tzinfo=tz.utc) + model_settings.CA_DEFAULT_EXPIRES


def test_int() -> None:
    """Test invocation with no args."""
    assert parse_expires(10) == datetime(2023, 5, 10, 12, 30, tzinfo=tz.utc)


def test_timedelta() -> None:
    """Test invocation with no args."""
    assert parse_expires(timedelta(days=10)) == datetime(2023, 5, 10, 12, 30, tzinfo=tz.utc)


def test_datetime() -> None:
    """Test invocation with no args."""
    expires = datetime(2023, 5, 10, 12, 30, tzinfo=tz.utc)
    parsed = parse_expires(expires)
    assert parsed == expires
    assert parsed.tzinfo == tz.utc


def test_datetime_with_non_local_timezone() -> None:
    """Test parsing a tz-aware datetime object with a custom timezone."""
    tzinfo = tz(timedelta(hours=2), name="Europe/Vienna")
    expires = datetime(2023, 5, 10, 12, 30, tzinfo=tzinfo)
    parsed = parse_expires(expires)
    assert parsed == expires
    assert parsed.tzinfo == tz.utc


def test_naive_datetime() -> None:
    """Test ValueError when parsing a naive datetime."""
    with pytest.raises(ValueError, match=r"^expires must not be a naive datetime$"):
        parse_expires(datetime(2023, 4, 30))
