# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca.  If not,
# see <http://www.gnu.org/licenses/>.

"""Some sanitity tests for constants."""

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from django.test import TestCase

from .. import constants

KNOWN_EXTENSION_OIDS = list(
    filter(
        lambda attr: isinstance(attr, x509.ObjectIdentifier),
        [getattr(ExtensionOID, attr) for attr in dir(ExtensionOID)],
    )
)
KNOWN_EXTENDED_KEY_USAGE_OIDS = list(
    filter(
        lambda attr: isinstance(attr, x509.ObjectIdentifier),
        [getattr(constants.ExtendedKeyUsageOID, attr) for attr in dir(constants.ExtendedKeyUsageOID)],
    )
)


class ReasonFlagsTestCase(TestCase):
    """Test readon flags."""

    def test_completeness(self) -> None:
        """Test that our list completely mirrors the cryptography list."""
        self.assertEqual(
            list(sorted([(k, v.value) for k, v in constants.ReasonFlags.__members__.items()])),
            list(sorted([(k, v.value) for k, v in x509.ReasonFlags.__members__.items()])),
        )


class CompletenessTestCase(TestCase):
    """Test for completeness of various constants."""

    def test_extended_key_usage_oids(self) -> None:
        """Test ExtendedKeyUsageOID for duplicates."""
        self.assertCountEqual(KNOWN_EXTENDED_KEY_USAGE_OIDS, list(set(KNOWN_EXTENDED_KEY_USAGE_OIDS)))

    def test_extended_key_usage_names(self) -> None:
        """Test completeness of EXTENDED_KEY_USAGE_NAMES constant."""
        self.assertCountEqual(KNOWN_EXTENDED_KEY_USAGE_OIDS, constants.EXTENDED_KEY_USAGE_NAMES.keys())

    def test_extended_key_usage_human_readable_names(self) -> None:
        """Test completeness of EXTENDED_KEY_USAGE_HUMAN_READABLE_NAMES constant."""
        self.assertCountEqual(
            KNOWN_EXTENDED_KEY_USAGE_OIDS, constants.EXTENDED_KEY_USAGE_HUMAN_READABLE_NAMES.keys()
        )

    def test_extension_keys(self) -> None:
        """Test completeness of KNOWN_EXTENSION_OIDS constant."""
        self.assertCountEqual(KNOWN_EXTENSION_OIDS, constants.EXTENSION_KEYS.keys())

    def test_oid_to_extension_names(self) -> None:
        """Test completeness of EXTENSION_NAMES."""
        self.assertCountEqual(KNOWN_EXTENSION_OIDS, constants.EXTENSION_NAMES.keys())

    def test_oid_default_critical(self) -> None:
        """Test completeness of EXTENSION_DEFAULT_CRITICAL."""
        self.assertCountEqual(KNOWN_EXTENSION_OIDS, constants.EXTENSION_DEFAULT_CRITICAL.keys())

    def test_oid_critical_help(self) -> None:
        """Test completeness of EXTENSION_CRITICAL_HELP."""
        self.assertCountEqual(KNOWN_EXTENSION_OIDS, constants.EXTENSION_CRITICAL_HELP.keys())
