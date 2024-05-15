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

import os
from datetime import timedelta
from pathlib import Path
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase

import pytest
from pytest_django.fixtures import SettingsWrapper

from ca.settings_utils import (
    get_settings_files,
    load_secret_key,
    load_settings_from_environment,
    load_settings_from_files,
    update_database_setting_from_environment,
)
from django_ca import ca_settings, conf
from django_ca.conf import model_settings
from django_ca.tests.base.assertions import assert_improperly_configured
from django_ca.tests.base.constants import FIXTURES_DIR
from django_ca.tests.base.mixins import TestCaseMixin


@pytest.mark.parametrize("value", (True, False) * 5)
def test_settings_module(settings: SettingsWrapper, value: bool) -> None:
    """Test setting a value in the settings module."""
    settings.CA_ENABLE_REST_API = value
    assert conf.model_settings.CA_ENABLE_REST_API is value
    assert model_settings.CA_ENABLE_REST_API is value


def test_tab_completion() -> None:
    """Test tab completion for ipython."""
    assert "CA_ENABLE_REST_API" in dir(model_settings)


def test_no_settings_files(tmp_path: Path) -> None:
    """Test no settings.yaml exists and no DJANGO_CA_SETTINGS env variable set."""
    assert not list(get_settings_files(tmp_path, ""))


def test_with_settings_files() -> None:
    """Test a full list of settings files."""
    base_dir = FIXTURES_DIR / "settings" / "base"
    single_file = FIXTURES_DIR / "settings" / "dirs" / "single-file.yaml"
    settings_dir = FIXTURES_DIR / "settings" / "dirs" / "settings_dir"
    settings_files = list(get_settings_files(base_dir, f"{single_file}:{settings_dir}"))
    assert settings_files == [
        single_file.parent / "single-file.yaml",
        settings_dir / "01-settings.yaml",
        settings_dir / "02-settings.yaml",
        base_dir / "ca" / "settings.yaml",
    ]

    # Assert that all files actually exist
    for path in settings_files:
        assert path.exists() is True


def test_load_settings_from_files() -> None:
    """Test loading settings from YAML files."""
    settings_dir = FIXTURES_DIR / "settings" / "dirs" / "settings_dir"
    single_file = FIXTURES_DIR / "settings" / "dirs" / "single-file.yaml"
    empty_file = FIXTURES_DIR / "settings" / "dirs" / "empty-file.yaml"

    with mock.patch.dict(os.environ, {"DJANGO_CA_SETTINGS": f"{single_file}:{settings_dir}:{empty_file}"}):
        assert dict(load_settings_from_files(FIXTURES_DIR)) == {
            "SETTINGS_DIR_ONE": True,
            "SETTINGS_DIR_TWO": True,
            "SINGLE_FILE": True,
            "SETTINGS_FILES": (
                single_file.parent / "single-file.yaml",
                settings_dir / "01-settings.yaml",
                settings_dir / "02-settings.yaml",
            ),
        }


def test_load_settings_from_files_file_does_not_exist() -> None:
    """Test loading settings if the file does not exist."""
    path = "/does-not-exist.yaml"
    with mock.patch.dict(os.environ, {"DJANGO_CA_SETTINGS": path}):
        with pytest.raises(ImproperlyConfigured, match=rf"^{path}: No such file or directory\.$"):
            dict(load_settings_from_files(FIXTURES_DIR))


def test_load_settings_from_files_with_invalid_yaml(tmp_path: Path) -> None:
    """Test loading settings if the file is not valid YAML."""
    path = str(tmp_path / "invalid-file.yaml")
    with open(path, "w", encoding="utf-8") as stream:
        stream.write("test: 'unbalanced quote")
    with mock.patch.dict(os.environ, {"DJANGO_CA_SETTINGS": path}):
        with pytest.raises(ImproperlyConfigured, match=rf"^{path}: Invalid YAML\.$"):
            dict(load_settings_from_files(FIXTURES_DIR))


def test_load_settings_from_files_with_invalid_type() -> None:
    """Test loading settings if the file has an invalid type."""
    path = str(FIXTURES_DIR / "settings" / "dirs" / "invalid-type.yaml")
    with mock.patch.dict(os.environ, {"DJANGO_CA_SETTINGS": path}):
        with pytest.raises(ImproperlyConfigured, match=rf"^{path}: File is not a key/value mapping\.$"):
            dict(load_settings_from_files(FIXTURES_DIR))


def test_load_settings_from_files_with_pyyaml_not_installed() -> None:
    """Test behaviour when PyYAML is not installed."""
    with mock.patch("ca.settings_utils.yaml", False):
        assert not dict(load_settings_from_files(FIXTURES_DIR))


def test_load_settings_from_environment() -> None:
    """Test loading settings from the environment."""
    with mock.patch.dict(
        os.environ,
        {
            "DJANGO_CA_SETTINGS": "ignored",
            "DJANGO_CA_ALLOWED_HOSTS": "example.com example.net",
            "DJANGO_CA_CA_ENABLE_ACME": "TRUE",
            "DJANGO_CA_CA_ENABLE_REST_API": "1",
            "DJANGO_CA_ENABLE_ADMIN": "yEs",
            "DJANGO_CA_SOME_OTHER_VALUE": "FOOBAR",
        },
    ):
        assert dict(load_settings_from_environment()) == {
            "ALLOWED_HOSTS": ["example.com", "example.net"],
            "CA_ENABLE_ACME": True,
            "CA_ENABLE_REST_API": True,
            "ENABLE_ADMIN": True,
            "SOME_OTHER_VALUE": "FOOBAR",
        }


def test_update_database_setting_from_environment_with_postgres_with_defaults() -> None:
    """Test loading database settings for PostgreSQL with default values."""
    databases = {"default": {"ENGINE": "django.db.backends.postgresql"}}
    with mock.patch.dict(os.environ, {}):
        update_database_setting_from_environment(databases)
    assert databases["default"] == {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "postgres",
        "PASSWORD": "postgres",
        "USER": "postgres",
    }


def test_update_database_setting_from_environment_with_postgres_with_values() -> None:
    """Test loading database settings for PostgreSQL with values from the environment."""
    databases = {"default": {"ENGINE": "django.db.backends.postgresql"}}
    with mock.patch.dict(
        os.environ,
        {
            "POSTGRES_PASSWORD": "custom-password",
            "POSTGRES_USER": "custom-user",
            "POSTGRES_DB": "custom-name",
        },
    ):
        update_database_setting_from_environment(databases)
    assert databases["default"] == {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "custom-name",
        "PASSWORD": "custom-password",
        "USER": "custom-user",
    }


def test_update_database_setting_from_environment_with_postgres_already_configured() -> None:
    """Test loading database settings for PostgreSQL with values already configured."""
    databases = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": "name",
            "PASSWORD": "password",
            "USER": "user",
        }
    }
    with mock.patch.dict(
        os.environ,
        {
            "POSTGRES_PASSWORD": "custom-password",
            "POSTGRES_USER": "custom-user",
            "POSTGRES_DB": "custom-name",
        },
    ):
        update_database_setting_from_environment(databases)
    assert databases["default"] == {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "name",
        "PASSWORD": "password",
        "USER": "user",
    }


def test_update_database_setting_from_environment_with_postgres_with_values_from_files(
    tmp_path: Path,
) -> None:
    """Test loading database settings for PostgreSQL with values from a file."""
    databases = {"default": {"ENGINE": "django.db.backends.postgresql"}}
    for key in ("db", "user", "password"):
        path = str(tmp_path / key)
        with open(path, "w", encoding="utf-8") as stream:
            stream.write(f"custom-{key}")

    with mock.patch.dict(
        os.environ,
        {
            "POSTGRES_PASSWORD_FILE": str(tmp_path / "password"),
            "POSTGRES_USER_FILE": str(tmp_path / "user"),
            "POSTGRES_DB_FILE": str(tmp_path / "db"),
        },
    ):
        update_database_setting_from_environment(databases)
    assert databases["default"] == {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "custom-db",
        "PASSWORD": "custom-password",
        "USER": "custom-user",
    }


def test_update_database_setting_from_environment_with_mysql_with_defaults() -> None:
    """Test loading database settings for MySQL with no default values."""
    databases = {"default": {"ENGINE": "django.db.backends.mysql"}}
    with mock.patch.dict(os.environ, {}):
        update_database_setting_from_environment(databases)
    assert databases["default"] == {"ENGINE": "django.db.backends.mysql"}


def test_update_database_setting_from_environment_with_mysql_with_values() -> None:
    """Test loading database settings for MySQL with values from the environment."""
    databases = {"default": {"ENGINE": "django.db.backends.mysql"}}
    with mock.patch.dict(
        os.environ,
        {
            "MYSQL_PASSWORD": "custom-password",
            "MYSQL_USER": "custom-user",
            "MYSQL_DATABASE": "custom-name",
        },
    ):
        update_database_setting_from_environment(databases)
    assert databases["default"] == {
        "ENGINE": "django.db.backends.mysql",
        "NAME": "custom-name",
        "PASSWORD": "custom-password",
        "USER": "custom-user",
    }


def test_update_database_setting_from_environment_with_mysql_with_values_from_files(tmp_path: Path) -> None:
    """Test loading database settings for MySQL with values from a file."""
    databases = {"default": {"ENGINE": "django.db.backends.mysql"}}
    for key in ("db", "user", "password"):
        path = str(tmp_path / key)
        with open(path, "w", encoding="utf-8") as stream:
            stream.write(f"custom-{key}")

    with mock.patch.dict(
        os.environ,
        {
            "MYSQL_PASSWORD_FILE": str(tmp_path / "password"),
            "MYSQL_USER_FILE": str(tmp_path / "user"),
            "MYSQL_DATABASE_FILE": str(tmp_path / "db"),
        },
    ):
        update_database_setting_from_environment(databases)
    assert databases["default"] == {
        "ENGINE": "django.db.backends.mysql",
        "NAME": "custom-db",
        "PASSWORD": "custom-password",
        "USER": "custom-user",
    }


def test_load_secret_key_already_set() -> None:
    """Test loading a SECRET_KEY that is already set."""
    assert load_secret_key("set", "file_path")


def test_load_secret_key_with_secret_key_file(tmp_path: Path) -> None:
    """Test loading a SECRET_KEY from a file."""
    secret_key_file = tmp_path / "secret_key"
    with open(secret_key_file, "w", encoding="utf-8") as stream:
        stream.write("123")

    assert load_secret_key(None, str(secret_key_file)) == "123"


def test_load_secret_key_with_no_secret_key_file() -> None:
    """Test exception when no SECRET_KEY can be determined."""
    with pytest.raises(ImproperlyConfigured, match=r"Unable to determine SECRET_KEY\.$"):
        load_secret_key(None, None)


def test_ca_passwords(settings: SettingsWrapper) -> None:
    """Test type coercion and sanitization of keys."""
    settings.CA_PASSWORDS = {
        "AA:BB:CC": "secret-str",
        "11:22:33": b"secret-bytes",
    }
    assert ca_settings.CA_PASSWORDS == {"112233": b"secret-bytes", "AABBCC": b"secret-str"}


def test_ca_passwords_with_invalid_type(settings: SettingsWrapper) -> None:
    """Test setting an invalid password type."""
    with assert_improperly_configured(r"CA_PASSWORDS: None: value must be bytes or str\."):
        settings.CA_PASSWORDS = {"AA:BB:CC": None}


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

    def test_ocsp_responder_certificate_renewal(self) -> None:
        """Test the CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL setting."""
        with self.settings(CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL=600):
            self.assertEqual(model_settings.CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL, timedelta(seconds=600))

    def test_ca_default_subject(self) -> None:
        """Test CA_DEFAULT_SUBJECT setting."""
        with self.settings(CA_DEFAULT_SUBJECT=(("C", "AT"), ("ST", "Vienna"))):
            self.assertEqual(
                ca_settings.CA_DEFAULT_SUBJECT,
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COUNTRY_NAME, "AT"),
                        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Vienna"),
                    ]
                ),
            )


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
        with assert_improperly_configured(r"^foo: CA_DEFAULT_PROFILE is not defined as a profile\.$"):
            with self.settings(CA_DEFAULT_PROFILE="foo"):
                pass

    def test_default_elliptic_curve(self) -> None:
        """Test invalid ``CA_DEFAULT_ELLIPTIC_CURVE``."""
        with assert_improperly_configured(r"CA_DEFAULT_ELLIPTIC_CURVE"):
            with self.settings(CA_DEFAULT_ELLIPTIC_CURVE="foo"):
                pass

    def test_default_name_order(self) -> None:
        """Test invalid values for a default name order."""
        with assert_improperly_configured(r"^CA_DEFAULT_NAME_ORDER: setting must be a tuple\.$"):
            with self.settings(CA_DEFAULT_NAME_ORDER=True):
                pass

    def test_min_default_key_size(self) -> None:
        """Test ``A_DEFAULT_KEY_SIZE``."""
        with assert_improperly_configured("CA_DEFAULT_KEY_SIZE cannot be lower then 1024"):
            with self.settings(CA_MIN_KEY_SIZE=1024, CA_DEFAULT_KEY_SIZE=512):
                pass

    def test_default_signature_hash_algorithm(self) -> None:
        """Test invalid ``CA_DEFAULT_SIGNATURE_HASH_ALGORITHM``."""
        with self.settings(CA_DEFAULT_SIGNATURE_HASH_ALGORITHM="SHA-224"):
            self.assertIsInstance(ca_settings.CA_DEFAULT_SIGNATURE_HASH_ALGORITHM, hashes.SHA224)

        msg = r"^CA_DEFAULT_SIGNATURE_HASH_ALGORITHM: foo: Unknown hash algorithm\.$"
        with assert_improperly_configured(msg):
            with self.settings(CA_DEFAULT_SIGNATURE_HASH_ALGORITHM="foo"):
                pass

    def test_default_dsa_signature_hash_algorithm(self) -> None:
        """Test invalid ``CA_DEFAULT_DSA_SIGNATURE_HASH_ALGORITHM``."""
        msg = r"^CA_DEFAULT_DSA_SIGNATURE_HASH_ALGORITHM: foo: Unknown hash algorithm\.$"
        with assert_improperly_configured(msg):
            with self.settings(CA_DEFAULT_DSA_SIGNATURE_HASH_ALGORITHM="foo"):
                pass

    def test_default_expires(self) -> None:
        """Test invalid ``CA_DEFAULT_EXPIRES``."""
        with assert_improperly_configured(r"^CA_DEFAULT_EXPIRES: foo: Must be int or timedelta$"):
            with self.settings(CA_DEFAULT_EXPIRES="foo"):
                pass

        with assert_improperly_configured(
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
            with assert_improperly_configured(msg), self.settings(CA_USE_CELERY=True):
                pass

    def test_invalid_setting(self) -> None:
        """Test setting an invalid CA."""
        with assert_improperly_configured(r"^CA_DEFAULT_CA: ABCX: Serial contains invalid characters\.$"):
            with self.settings(CA_DEFAULT_CA="0a:bc:x"):
                pass

    def test_default_subject_with_duplicate_country(self) -> None:
        """Test the check for OIDs that must not occur multiple times."""
        with assert_improperly_configured(r'^CA_DEFAULT_SUBJECT contains multiple "countryName" fields\.$'):
            with self.settings(CA_DEFAULT_SUBJECT=(("C", "AT"), ("C", "DE"))):
                pass

    def test_default_subject_with_empty_common_name(self) -> None:
        """Test the check for empty common names."""
        with assert_improperly_configured(r"^CA_DEFAULT_SUBJECT: CommonName must not be an empty value\.$"):
            with self.settings(CA_DEFAULT_SUBJECT=(("CN", ""),)):
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
        with assert_improperly_configured(msg):
            with self.settings(CA_DEFAULT_SUBJECT=True):
                pass

        msg = r"^CA_DEFAULT_SUBJECT: foo: Items must be a x509.NameAttribute, list or tuple\."
        with assert_improperly_configured(msg):
            with self.settings(CA_DEFAULT_SUBJECT=["foo"]):
                pass

        msg = r"^CA_DEFAULT_SUBJECT: \['foo'\]: Must be lists/tuples with two items, got 1\."
        with assert_improperly_configured(msg):
            with self.settings(CA_DEFAULT_SUBJECT=[["foo"]]):
                pass

        with assert_improperly_configured(r"^True: Must be a x509.ObjectIdentifier or str\."):
            with self.settings(CA_DEFAULT_SUBJECT=[[True, "foo"]]):
                pass

        with assert_improperly_configured(r"^CA_DEFAULT_SUBJECT: True: Item values must be strings\."):
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
        """Test that an empty list is normalized to None."""
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
        """Test using an invalid subject key."""
        with assert_improperly_configured(r"^invalid: Unknown attribute type\.$"):
            with self.settings(CA_DEFAULT_SUBJECT=[("invalid", "wrong")]):
                pass

    def test_invalid_ocsp_responder_certificate_renewal(self) -> None:
        """Test the CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL setting."""
        with assert_improperly_configured(r"Input should be a valid timedelta"):
            with self.settings(CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL="600"):
                pass
