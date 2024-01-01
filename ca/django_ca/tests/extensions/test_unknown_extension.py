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

"""Test some unlikely edge cases for serialization and textualization."""

from cryptography import x509

from django.test import TestCase

from django_ca.extensions import extension_as_text, parse_extension


class TypeErrorTests(TestCase):
    """Test some unlikely edge cases for serialization and textualization."""

    dotted_string = "1.2.3"
    oid = x509.ObjectIdentifier(dotted_string)

    class UnknownExtensionType(x509.ExtensionType):
        """A self-defined, completely unknown extension type, only for testing."""

        oid = x509.ObjectIdentifier("1.2.3")

        def public_bytes(self) -> bytes:
            return b""

    ext_type = UnknownExtensionType()
    ext = x509.Extension(oid=oid, critical=True, value=b"foo")  # type: ignore[type-var]

    def test_parse_unknown_key(self) -> None:
        """Test exception for parsing an extension with an unsupported key."""
        with self.assertRaisesRegex(ValueError, r"^wrong_key: Unknown extension key\.$"):
            parse_extension("wrong_key", {})

    def test_no_extension_as_text(self) -> None:
        """Test textualizing an extension that is not an extension type."""
        with self.assertRaisesRegex(TypeError, r"^bytes: Not a cryptography\.x509\.ExtensionType\.$"):
            extension_as_text(b"foo")  # type: ignore[arg-type]

    def test_unknown_extension_type_as_text(self) -> None:
        """Test textualizing an extension of unknown type."""
        with self.assertRaisesRegex(
            TypeError, r"^UnknownExtensionType \(oid: 1\.2\.3\): Unknown extension type\.$"
        ):
            extension_as_text(self.ext_type)
