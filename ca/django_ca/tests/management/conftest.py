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

"""Pytest configuration for argparse action tests."""

import argparse
import os
import sys
from io import StringIO
from typing import Any
from unittest import mock

import pytest


def assert_parser_error(
    parser: argparse.ArgumentParser, args: list[str], expected: str, **kwargs: Any
) -> str:
    """Assert that given args throw a parser error."""
    kwargs.setdefault("script", os.path.basename(sys.argv[0]))
    expected = expected.format(**kwargs)

    buf = StringIO()
    with pytest.raises(SystemExit), mock.patch("sys.stderr", buf):
        parser.parse_args(args)

    output = buf.getvalue()
    assert output == expected
    return output
