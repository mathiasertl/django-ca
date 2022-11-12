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
from ..extensions import KEY_TO_OID

KNOWN_EXTENSION_OIDS = list(
    filter(
        lambda attr: isinstance(attr, x509.ObjectIdentifier),
        [getattr(ExtensionOID, attr) for attr in dir(ExtensionOID)],
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


class ExtensionMappingsTestCase(TestCase):
    """Test various mappings from ExtensionOIDs to something."""

    def test_completeness_extension_keys(self) -> None:
        """Test completeness of KNOWN_EXTENSION_OIDS constant."""
        self.assertCountEqual(KNOWN_EXTENSION_OIDS, constants.EXTENSION_KEYS.keys())

        # Make sure that it matches old extensions class keys
        for key, value in constants.EXTENSION_KEYS.items():
            self.assertEqual(key, KEY_TO_OID[value])

    def test_completeness_oid_to_extension_names(self) -> None:
        """Test completeness of OID_TO_EXTENSION_NAMES."""
        self.assertCountEqual(KNOWN_EXTENSION_OIDS, constants.OID_TO_EXTENSION_NAMES.keys())

    def test_completeness_oid_default_critical(self) -> None:
        """Test completeness of OID_DEFAULT_CRITICAL."""
        self.assertCountEqual(KNOWN_EXTENSION_OIDS, constants.OID_DEFAULT_CRITICAL.keys())

    def test_completeness_oid_critical_help(self) -> None:
        """Test completeness of OID_CRITICAL_HELP."""
        self.assertCountEqual(KNOWN_EXTENSION_OIDS, constants.OID_CRITICAL_HELP.keys())
