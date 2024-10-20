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

"""Test :py:func:`django_ca.utils.validate_hostname`."""

import pytest

from django_ca.utils import split_str


@pytest.mark.parametrize(
    ("value", "seperator", "expected"),
    (
        ("foo", "/", ["foo"]),
        ("foo bar", "/", ["foo bar"]),
        ("foo/bar", "/", ["foo", "bar"]),
        ("foo'/'bar", "/", ["foo/bar"]),
        ('foo"/"bar', "/", ["foo/bar"]),
        ("'foo/bar'", "/", ["foo/bar"]),
        ('"foo/bar"', "/", ["foo/bar"]),
        ('"foo/bar"/bla', "/", ["foo/bar", "bla"]),
        # Test what happens when the delimiter is at the start/end of the string:
        ("foo/", "/", ["foo"]),
        ("/foo", "/", ["foo"]),
        ("/foo/", "/", ["foo"]),
        ("foo/bar/", "/", ["foo", "bar"]),
        ("/foo/bar", "/", ["foo", "bar"]),
        ("/foo/bar/", "/", ["foo", "bar"]),
        ("/C=AT/CN=example.com/", "/", ["C=AT", "CN=example.com"]),
        # test quoting
        (r'fo"o/b"ar', "/", ["foo/bar"]),
        (r'"foo\"bar"', "/", ['foo"bar']),  # escape quotes inside quotes
        # Test the escape character
        (r"foo\/bar", "/", ["foo/bar"]),
        (r"foo\\/bar", "/", ["foo\\", "bar"]),
        # Escape the double quote - so it has no special meaning
        (r"foo\"bar", "/", [r'foo"bar']),
        (r"foo\"/\"bar", "/", [r'foo"', '"bar']),
        # both tokens quoted in single quotes:
        (r"'foo\\'/'bar'", "/", [r"foo\\", "bar"]),
        # test special characters
        (r"foo\xbar", "/", ["fooxbar"]),
        # Inside a quoted or double-quoted string, single backslash is preserved
        (r'"foo\xbar"', "/", [r"foo\xbar"]),
        (r"'foo\xbar'", "/", [r"foo\xbar"]),
        # In a double-quoted string, backslash is interpreted as escape -> single backslash in result
        (r'"foo\\xbar"', "/", [r"foo\xbar"]),
        # ... but in single quote it's not an escape -> double backslash in result
        (r"'foo\\xbar'", "/", [r"foo\\xbar"]),
        ("'foo/bar'/bla", "/", ["foo/bar", "bla"]),
        # With quotes/double quotes, with one backslash
        (r'"foo\/bar"/bla', "/", [r"foo\/bar", "bla"]),
        (r"'foo\/bar'/bla", "/", [r"foo\/bar", "bla"]),
        # With double quotes and a double backslash -> backslash is escape char -> single backslash in result
        (r'"foo\\/bar"/bla', "/", [r"foo\/bar", "bla"]),
        # With single quotes and a double backslash -> backslash is *not* escape char -> double backslash
        (r"'foo\\/bar'/bla", "/", [r"foo\\/bar", "bla"]),
        # Test that default comment characters play no special role.
        ("foo#bar", "/", ["foo#bar"]),
        ("foo/#bar", "/", ["foo", "#bar"]),
        ("foo#/bar", "/", ["foo#", "bar"]),
        ("foo'#'bar", "/", ["foo#bar"]),
        ("'foo#bar'/bla#baz", "/", ["foo#bar", "bla#baz"]),
        # Test that non-wordchars also work properly.
        # From the docs: If whitespace_split is set to True, this will have no effect.
        ("foo=bar/what=ever", "/", ["foo=bar", "what=ever"]),
        # Test that punctuation chars do not affect the parsing.
        #
        # We test this here because documentation is not exactly clear about this parameter. But if we pass
        # `punctuation_chars=False` to shlex, this test fails, so we test for that too.
        ("foo|bar", "/", ["foo|bar"]),
        ("(foo|bar)/bla/baz(bla", "/", ["(foo|bar)", "bla", "baz(bla"]),
        ("(foo|{b,}ar)/bla/baz(bla", "/", ["(foo|{b,}ar)", "bla", "baz(bla"]),
    ),
)
def test_basic(value: str, seperator: str, expected: list[str]) -> None:
    """Some basic split_str() test cases."""
    assert list(split_str(value, seperator)) == expected


@pytest.mark.parametrize(
    ("value", "match"),
    (
        (r"'foo\'bar'", "^No closing quotation$"),
        (r"foo'bar", "^No closing quotation$"),
        (r'foo"bar', "^No closing quotation$"),
        (r"foo'bar/bla", "^No closing quotation$"),
        (r'foo"bar/bla', "^No closing quotation$"),
    ),
)
def test_quotation_errors(value: str, match: str) -> None:
    """Test quoting."""
    with pytest.raises(ValueError, match=match):
        list(split_str(value, "/"))
