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

"""Test cases for the datetime action."""

# pylint: disable=redefined-outer-name

import argparse
from argparse import ArgumentParser
from datetime import datetime, timezone
from typing import Literal

import freezegun
import pytest

from django_ca.management.actions import DatetimeAction
from django_ca.tests.management.conftest import assert_parser_error


@pytest.fixture
def parser() -> argparse.ArgumentParser:
    """Fixture to retrieve the parser."""
    datetime_parser = argparse.ArgumentParser()
    datetime_parser.add_argument("-v", "--value", action=DatetimeAction)
    return datetime_parser


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        ("2011-11-04", datetime(2011, 11, 4, 0, 0, tzinfo=timezone.utc)),
        ("2011-11-04T00:05:23", datetime(2011, 11, 4, 0, 5, 23, tzinfo=timezone.utc)),
        ("2011-11-04T00:05:23+00:00", datetime(2011, 11, 4, 0, 5, 23, tzinfo=timezone.utc)),
        # pragma: only py<3.11: Z is only supported with python 3.11
        # ("2011-11-04T00:05:23Z", datetime(2011, 11, 4, 0, 5, 23, tzinfo=timezone.utc)),
        ("2011-11-04 00:05:23.283+00:00", datetime(2011, 11, 4, 0, 5, 23, 283000, tzinfo=timezone.utc)),
    ),
)
def test_action(parser: ArgumentParser, value: str, expected: datetime) -> None:
    """Basic test for DatetimeAction."""
    assert parser.parse_args(["-v", value]).value == expected


@pytest.mark.parametrize(
    ("precision", "value", "expected"),
    (
        (None, "2011-11-04T01:05:23.283+00:00", datetime(2011, 11, 4, 1, 5, 23, 283000, tzinfo=timezone.utc)),
        ("s", "2011-11-04T01:05:23.283+00:00", datetime(2011, 11, 4, 1, 5, 23, tzinfo=timezone.utc)),
        ("m", "2011-11-04T01:05:23.283+00:00", datetime(2011, 11, 4, 1, 5, tzinfo=timezone.utc)),
        ("h", "2011-11-04T01:05:23.283+00:00", datetime(2011, 11, 4, 1, tzinfo=timezone.utc)),
    ),
)
def test_precision(precision: Literal["s", "m", "h"] | None, value: str, expected: datetime) -> None:
    """Test precision argument for DatetimeAction."""
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--value", action=DatetimeAction, precision=precision)

    assert parser.parse_args(["-v", value]).value == expected


@freezegun.freeze_time("2025-07-06T11:26")
def test_error(parser: ArgumentParser) -> None:
    """Test error when unparseable date is passed."""
    example = "2025-07-06T11:26:00+00:00"
    assert_parser_error(
        parser,
        ["-v", "foo"],
        f"""usage: pytest [-h] [-v YYYY-mm-ddTHH:MM:SS]
pytest: error: argument -v/--value: foo: Must be a valid ISO 8601 datetime format (example: {example}).
""",
    )
