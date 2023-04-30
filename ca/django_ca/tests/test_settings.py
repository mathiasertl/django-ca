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

"""Test cases for the ``ca_settings`` module."""

from datetime import timedelta
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from django.test import TestCase

from django_ca import ca_settings
from django_ca.tests.base.mixins import TestCaseMixin


class SettingsTestCase(TestCase):
    """Test some standard settings."""

    def test_none_profiles(self) -> None:
        """Test removing a profile by setting it to None."""
        self.assertIn("client", ca_settings.CA_PROFILES)

        with self.settings(CA_PROFILES={"client": None}):
            self.assertNotIn("client", ca_settings.CA_PROFILES)

    def test_ca_profile_update(self) -> None:
        """Test adding a profile in settings."""
        desc = "test description"
        with self.settings(CA_PROFILES={"client": {"desc": desc}}):
            self.assertEqual(ca_settings.CA_PROFILES["client"]["desc"], desc)

    def test_acme_order_validity(self) -> None:
        """Test that CA_ACME_ORDER_VALIDITY can be set to an int."""
        with self.settings(CA_ACME_ORDER_VALIDITY=1):
            self.assertEqual(ca_settings.ACME_ORDER_VALIDITY, timedelta(days=1))

    def test_acme_default_validity(self) -> None:
        """Test that CA_DEFAULT_CERT_VALIDITY can be set to an int."""
        with self.settings(CA_ACME_DEFAULT_CERT_VALIDITY=1):
            self.assertEqual(ca_settings.ACME_DEFAULT_CERT_VALIDITY, timedelta(days=1))

    def test_acme_max_validity(self) -> None:
        """Test that CA_MAX_CERT_VALIDITY can be set to an int."""
        with self.settings(CA_ACME_MAX_CERT_VALIDITY=1):
            self.assertEqual(ca_settings.ACME_MAX_CERT_VALIDITY, timedelta(days=1))

    def test_use_celery(self) -> None:
        """Test CA_USE_CELERY setting."""
        with self.settings(CA_USE_CELERY=False):
            self.assertFalse(ca_settings.CA_USE_CELERY)
        with self.settings(CA_USE_CELERY=True):
            self.assertTrue(ca_settings.CA_USE_CELERY)
        with self.settings(CA_USE_CELERY=None):
            self.assertTrue(ca_settings.CA_USE_CELERY)

        # mock a missing Celery installation
        with mock.patch.dict("sys.modules", celery=None), self.settings(CA_USE_CELERY=None):
            self.assertFalse(ca_settings.CA_USE_CELERY)
        with mock.patch.dict("sys.modules", celery=None), self.settings(CA_USE_CELERY=False):
            self.assertFalse(ca_settings.CA_USE_CELERY)


class DefaultCATestCase(TestCase):
    """Test the :ref:`CA_DEFAULT_CA <settings-ca-default-ca>` setting."""

    def test_no_setting(self) -> None:
        """Test empty setting."""
        with self.settings(CA_DEFAULT_CA=""):
            self.assertEqual(ca_settings.CA_DEFAULT_CA, "")

    def test_unsanitized_setting(self) -> None:
        """Test that values are sanitized properly."""
        with self.settings(CA_DEFAULT_CA="0a:bc"):
            self.assertEqual(ca_settings.CA_DEFAULT_CA, "ABC")

    def test_serial_zero(self) -> None:
        """Test that a '0' serial is not stripped."""
        with self.settings(CA_DEFAULT_CA="0"):
            self.assertEqual(ca_settings.CA_DEFAULT_CA, "0")


class ImproperlyConfiguredTestCase(TestCaseMixin, TestCase):
    """Test various invalid configurations."""

    def test_default_profile(self) -> None:
        """Test the check if the default profile is defined."""
        with self.assertImproperlyConfigured(r"^foo: CA_DEFAULT_PROFILE is not defined as a profile\.$"):
            with self.settings(CA_DEFAULT_PROFILE="foo"):
                pass

    def test_default_elliptic_curve(self) -> None:
        """Test invalid ``CA_DEFAULT_ELLIPTIC_CURVE``."""
        with self.assertImproperlyConfigured(r"^foo: Unknown CA_DEFAULT_ELLIPTIC_CURVE.$"):
            with self.settings(CA_DEFAULT_ELLIPTIC_CURVE="foo"):
                pass

        warn = r"^CA_DEFAULT_ECC_CURVE is deprecated, please use CA_DEFAULT_ELLIPTIC_CURVE instead. Support for this setting will be removed in django-ca==1\.25\.0\.$"  # noqa: E501
        with self.assertRemovedIn125Warning(warn):
            with self.settings(CA_DEFAULT_ECC_CURVE="SECP256R1"):
                self.assertEqual(ca_settings.CA_DEFAULT_ELLIPTIC_CURVE, ec.SECP256R1)

        with self.assertRemovedIn125Warning(warn), self.assertImproperlyConfigured(
            r"^ECDH: Not an elliptic curve\.$"
        ):
            with self.settings(CA_DEFAULT_ECC_CURVE="ECDH"):
                pass

        with self.assertRemovedIn125Warning(warn), self.assertImproperlyConfigured(
            r"^foo: Unknown elliptic curve\.$"
        ):
            with self.settings(CA_DEFAULT_ECC_CURVE="foo"):
                pass

    def test_default_name_order(self) -> None:
        """Test invalid values for a default name order"""
        with self.assertImproperlyConfigured(r"^CA_DEFAULT_NAME_ORDER: setting must be a tuple\.$"):
            with self.settings(CA_DEFAULT_NAME_ORDER=True):
                pass

    def test_min_default_key_size(self) -> None:
        """Test ``A_DEFAULT_KEY_SIZE``."""
        with self.assertImproperlyConfigured("^CA_DEFAULT_KEY_SIZE cannot be lower then 1024$"):
            with self.settings(CA_MIN_KEY_SIZE=1024, CA_DEFAULT_KEY_SIZE=512):
                pass

    def test_default_signature_hash_algorithm(self) -> None:
        """Test invalid ``CA_DEFAULT_SIGNATURE_HASH_ALGORITHM``."""
        with self.settings(CA_DEFAULT_SIGNATURE_HASH_ALGORITHM="SHA-224"):
            self.assertIsInstance(ca_settings.CA_DEFAULT_SIGNATURE_HASH_ALGORITHM, hashes.SHA224)

        with self.assertImproperlyConfigured(r"^foo: Unknown hash algorithm\.$"):
            with self.settings(CA_DEFAULT_SIGNATURE_HASH_ALGORITHM="foo"):
                pass

        warn = r"^CA_DIGEST_ALGORITHM is deprecated, please use CA_DEFAULT_SIGNATURE_HASH_ALGORITHM instead. Support for this setting will be removed in django-ca==1\.25\.0\.$"  # noqa: E501
        with self.assertRemovedIn125Warning(warn):
            with self.settings(CA_DEFAULT_SIGNATURE_HASH_ALGORITHM=None, CA_DIGEST_ALGORITHM="sha384"):
                self.assertIsInstance(ca_settings.CA_DEFAULT_SIGNATURE_HASH_ALGORITHM, hashes.SHA384)

        with self.assertRemovedIn125Warning(warn), self.assertImproperlyConfigured(
            r"^FOO: Unknown hash algorithm\."
        ):
            with self.settings(CA_DEFAULT_SIGNATURE_HASH_ALGORITHM=None, CA_DIGEST_ALGORITHM="foo"):
                self.assertIsInstance(ca_settings.CA_DEFAULT_SIGNATURE_HASH_ALGORITHM, hashes.SHA384)

    def test_default_dsa_signature_hash_algorithm(self) -> None:
        """Test invalid ``CA_DEFAULT_DSA_SIGNATURE_HASH_ALGORITHM``."""
        with self.assertImproperlyConfigured(r"^foo: Unknown hash algorithm\.$"):
            with self.settings(CA_DEFAULT_DSA_SIGNATURE_HASH_ALGORITHM="foo"):
                pass

    def test_default_expires(self) -> None:
        """Test invalid ``CA_DEFAULT_EXPIRES``."""
        with self.assertImproperlyConfigured(r"^CA_DEFAULT_EXPIRES: foo: Must be int or timedelta$"):
            with self.settings(CA_DEFAULT_EXPIRES="foo"):
                pass

        with self.assertImproperlyConfigured(
            r"^CA_DEFAULT_EXPIRES: -3 days, 0:00:00: Must have positive value$"
        ):
            with self.settings(CA_DEFAULT_EXPIRES=timedelta(days=-3)):
                pass

    def test_use_celery(self) -> None:
        """Test that CA_USE_CELERY=True and a missing Celery installation throws an error."""
        # Setting sys.modules['celery'] (modules cache) to None will cause the next import of that module
        # to trigger an import error:
        #   https://medium.com/python-pandemonium/how-to-test-your-imports-1461c1113be1
        #   https://docs.python.org/3.8/reference/import.html#the-module-cache
        with mock.patch.dict("sys.modules", celery=None):
            msg = r"^CA_USE_CELERY set to True, but Celery is not installed$"
            with self.assertImproperlyConfigured(msg), self.settings(CA_USE_CELERY=True):
                pass

    def test_invalid_setting(self) -> None:
        """Test setting an invalid CA."""
        with self.assertImproperlyConfigured(r"^CA_DEFAULT_CA: ABCX: Serial contains invalid characters\.$"):
            with self.settings(CA_DEFAULT_CA="0a:bc:x"):
                pass


class CaDefaultSubjectTestCase(TestCaseMixin, TestCase):
    """Test parsing the CA_DEFAULT_SUBJECT setting."""

    def test_subject_normalization(self) -> None:
        """Test that subjects are normalized to tuples of two-tuples."""
        with self.settings(
            CA_DEFAULT_SUBJECT=[["C", "AT"], ["O", "example"]],
            CA_PROFILES={"webserver": {"subject": [["C", "TL"], ["OU", "foobar"]]}},
        ):
            self.assertEqual(
                ca_settings.CA_DEFAULT_SUBJECT,
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COUNTRY_NAME, "AT"),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "example"),
                    ]
                ),
            )

    def test_invalid_subjects(self) -> None:
        """Test checks for invalid subjects."""
        msg = r"^CA_DEFAULT_SUBJECT: True: Value must be an x509.Name, list or tuple\."
        with self.assertImproperlyConfigured(msg):
            with self.settings(CA_DEFAULT_SUBJECT=True):
                pass

        msg = r"^CA_DEFAULT_SUBJECT: foo: Items must be a x509.NameAttribute, list or tuple\."
        with self.assertImproperlyConfigured(msg):
            with self.settings(CA_DEFAULT_SUBJECT=["foo"]):
                pass

        msg = r"^CA_DEFAULT_SUBJECT: \['foo'\]: Must be lists/tuples with two items, got 1\."
        with self.assertImproperlyConfigured(msg):
            with self.settings(CA_DEFAULT_SUBJECT=[["foo"]]):
                pass

        with self.assertImproperlyConfigured(r"^True: Must be a x509.ObjectIdentifier or str\."):
            with self.settings(CA_DEFAULT_SUBJECT=[[True, "foo"]]):
                pass

        with self.assertImproperlyConfigured(r"^CA_DEFAULT_SUBJECT: True: Item values must be strings\."):
            with self.settings(CA_DEFAULT_SUBJECT=[["foo", True]]):
                pass

    def test_none_value(self) -> None:
        """Test using a None value (the default outside of tests)."""
        with self.settings(CA_DEFAULT_SUBJECT=None):
            self.assertIsNone(ca_settings.CA_DEFAULT_SUBJECT)

    def test_value_as_list(self) -> None:
        """Test that a list subject is converted to a tuple."""
        with self.settings(CA_DEFAULT_SUBJECT=[("CN", "example.com")]):
            self.assertEqual(
                ca_settings.CA_DEFAULT_SUBJECT,
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")]),
            )

    def test_empty_iterable(self) -> None:
        """Test that an empty list is normalized to None"""
        with self.settings(CA_DEFAULT_SUBJECT=[]):
            self.assertIsNone(ca_settings.CA_DEFAULT_SUBJECT)
        with self.settings(CA_DEFAULT_SUBJECT=tuple()):
            self.assertIsNone(ca_settings.CA_DEFAULT_SUBJECT)

    def test_value_as_x509_name(self) -> None:
        """Test using a x509.Name as value."""
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
        with self.settings(CA_DEFAULT_SUBJECT=name):
            self.assertEqual(ca_settings.CA_DEFAULT_SUBJECT, name)

    def test_name_attribute_keys(self) -> None:
        """Test using a x509.NameAttribute as key in a list element."""
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
        with self.settings(CA_DEFAULT_SUBJECT=[(x509.NameAttribute(NameOID.COMMON_NAME, "example.com"))]):
            self.assertEqual(ca_settings.CA_DEFAULT_SUBJECT, name)

    def test_invalid_key(self) -> None:
        """Test using an invalid subject key"""
        with self.assertImproperlyConfigured(r"^invalid: Unknown attribute type\.$"):
            with self.settings(CA_DEFAULT_SUBJECT=[("invalid", "wrong")]):
                pass
