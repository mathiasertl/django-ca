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


"""Test cases for ``conf.model_settings``."""

import os
from datetime import timedelta
from pathlib import Path
from typing import Any
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from django.core.exceptions import ImproperlyConfigured
from django.core.signals import setting_changed

import pytest
from pytest_django.fixtures import SettingsWrapper

from ca.settings_utils import (
    get_settings_files,
    load_secret_key,
    load_settings_from_environment,
    load_settings_from_files,
    update_database_setting_from_environment,
)
from django_ca import conf
from django_ca.conf import KeyBackendConfigurationModel, model_settings
from django_ca.tests.base.assertions import assert_improperly_configured, assert_removed_in_220
from django_ca.tests.base.constants import FIXTURES_DIR
from django_ca.tests.base.utils import cn, country, state


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


def test_ca_acme_order_validity_as_int(settings: SettingsWrapper) -> None:
    """Test that CA_ACME_ORDER_VALIDITY can be set to an int."""
    settings.CA_ACME_ORDER_VALIDITY = 1
    assert model_settings.CA_ACME_ORDER_VALIDITY == timedelta(days=1)


@pytest.mark.parametrize("setting", ("CA_ACME_DEFAULT_CERT_VALIDITY", "CA_ACME_MAX_CERT_VALIDITY"))
def test_ca_acme_cert_validity_timedelta_settings_as_int(settings: SettingsWrapper, setting: str) -> None:
    """Test that CA_DEFAULT_CERT_VALIDITY can be set to an int."""
    setattr(settings, setting, 1)
    assert getattr(model_settings, setting) == timedelta(days=1)


@pytest.mark.parametrize("setting", ("CA_ACME_DEFAULT_CERT_VALIDITY", "CA_ACME_MAX_CERT_VALIDITY"))
@pytest.mark.parametrize(
    "value,message",
    (
        (timedelta(seconds=1), "Input should be greater than or equal to 1 day"),
        (timedelta(days=366), "Input should be less than or equal to 365 days"),
    ),
)
def test_ca_acme_cert_validity_limits(
    settings: SettingsWrapper, setting: str, value: timedelta, message: str
) -> None:
    """Test limits for CA_ACME_DEFAULT_CERT_VALIDITY and CA_ACME_MAX_CERT_VALIDITY."""
    with assert_improperly_configured(message):
        setattr(settings, setting, value)


@pytest.mark.parametrize(
    "value,message",
    (
        (timedelta(seconds=59), "Input should be greater than or equal to 1 minute"),
        (timedelta(days=2), "Input should be less than or equal to 1 day"),
    ),
)
def test_ca_acme_order_validity_limits(settings: SettingsWrapper, value: timedelta, message: str) -> None:
    """Test that CA_ACME_ORDER_VALIDITY can be set to an int."""
    with assert_improperly_configured(message):
        settings.CA_ACME_ORDER_VALIDITY = value


@pytest.mark.parametrize(
    "value,parsed",
    (
        ("0a:bc", "ABC"),  # leading zero is stripped
        ("0", "0"),  # single zero is *not* stripped
        (0, "0"),
        (107445593797734449393285726012835494904131403687, "12D206ED53306C95DE900C857B40BDA423D6BFA7"),
        (528891388214294454525193873483541400360266179579, "5CA44F619C74689E8C02DDC42FBE51D3053B23FB"),
    ),
)
def test_ca_default_ca(settings: SettingsWrapper, value: int, parsed: str) -> None:
    """Test that a '0' serial is not stripped."""
    settings.CA_DEFAULT_CA = value
    assert model_settings.CA_DEFAULT_CA == parsed


def test_ca_default_ca_with_invalid_value(settings: SettingsWrapper) -> None:
    """Test setting an invalid CA."""
    with assert_improperly_configured(r"String should match pattern"):
        settings.CA_DEFAULT_CA = "0a:bc:x"


def test_ca_default_dsa_signature_hash_algorithm_with_invalid_value(settings: SettingsWrapper) -> None:
    """Test invalid ``CA_DEFAULT_DSA_SIGNATURE_HASH_ALGORITHM``."""
    msg = r"Input should be an instance of HashAlgorithm"
    with assert_improperly_configured(msg):
        settings.CA_DEFAULT_DSA_SIGNATURE_HASH_ALGORITHM = "foo"


def test_ca_default_elliptic_curve_with_invalid_value(settings: SettingsWrapper) -> None:
    """Test invalid ``CA_DEFAULT_ELLIPTIC_CURVE``."""
    with assert_improperly_configured(r"CA_DEFAULT_ELLIPTIC_CURVE"):
        settings.CA_DEFAULT_ELLIPTIC_CURVE = "foo"


def test_ca_default_expires_with_invalid_value(settings: SettingsWrapper) -> None:
    """Test invalid ``CA_DEFAULT_EXPIRES``."""
    with assert_improperly_configured(r"Input should be a valid timedelta, invalid digit in duration"):
        settings.CA_DEFAULT_EXPIRES = "foo"

    with assert_improperly_configured(r"Input should be greater than or equal to 1 day"):
        settings.CA_DEFAULT_EXPIRES = timedelta(days=-3)


def test_ca_default_key_backend_is_not_configured(settings: SettingsWrapper) -> None:
    """Test error when CA_DEFAULT_KEY_BACKEND refers to a backend that is *not* configured."""
    assert "other-backend" not in model_settings.CA_KEY_BACKENDS
    with assert_improperly_configured(r"The default key backend is not configured\."):
        settings.CA_DEFAULT_KEY_BACKEND = "other-backend"


def test_ca_default_key_size_with_larger_ca_min_key_size(settings: SettingsWrapper) -> None:
    """Test error when ``A_DEFAULT_KEY_SIZE`` is smaller then minimum key size."""
    with assert_improperly_configured("CA_DEFAULT_KEY_SIZE cannot be lower then 8192"):
        settings.CA_MIN_KEY_SIZE = 8192


def test_ca_default_name_order(settings: SettingsWrapper) -> None:
    """Test variant values that can be used for a default name."""
    settings.CA_DEFAULT_NAME_ORDER = ("dnQualifier", "2.5.4.6", NameOID.COMMON_NAME)
    assert model_settings.CA_DEFAULT_NAME_ORDER == (
        NameOID.DN_QUALIFIER,
        NameOID.COUNTRY_NAME,
        NameOID.COMMON_NAME,
    )


@pytest.mark.parametrize(
    "value,msg",
    (
        (True, r"Input should be a valid tuple"),
        (("invalid-oid",), "invalid-oid: Invalid object identifier"),
    ),
)
def test_ca_default_name_order_with_invalid_value(settings: SettingsWrapper, value: Any, msg: str) -> None:
    """Test invalid values for a default name order."""
    with assert_improperly_configured(msg):
        settings.CA_DEFAULT_NAME_ORDER = value


def test_ca_default_profile_not_defined(settings: SettingsWrapper) -> None:
    """Test the check if the default profile is defined."""
    with assert_improperly_configured(r"foo: CA_DEFAULT_PROFILE is not defined as a profile\."):
        settings.CA_DEFAULT_PROFILE = "foo"


@pytest.mark.parametrize("value,expected", (("SHA-224", hashes.SHA224), ("SHA3/384", hashes.SHA3_384)))
def test_ca_default_signature_hash_algorithm(
    settings: SettingsWrapper, value: Any, expected: type[hashes.HashAlgorithm]
) -> None:
    """Test ``CA_DEFAULT_SIGNATURE_HASH_ALGORITHM``."""
    settings.CA_DEFAULT_SIGNATURE_HASH_ALGORITHM = value
    assert isinstance(model_settings.CA_DEFAULT_SIGNATURE_HASH_ALGORITHM, expected)


def test_ca_default_signature_hash_algorithm_with_invalid_value(settings: SettingsWrapper) -> None:
    """Test invalid ``CA_DEFAULT_SIGNATURE_HASH_ALGORITHM``."""
    msg = r"Input should be an instance of HashAlgorithm"
    with assert_improperly_configured(msg):
        settings.CA_DEFAULT_SIGNATURE_HASH_ALGORITHM = "foo"


@pytest.mark.parametrize(
    "value,expected",
    (
        # Serialized version
        (
            [
                {"oid": "C", "value": "AT"},
                {"oid": NameOID.STATE_OR_PROVINCE_NAME.dotted_string, "value": "Vienna"},
            ],
            x509.Name([country("AT"), state("Vienna")]),
        ),
        # x509Name objects
        (x509.Name([country("AT"), state("Vienna")]), x509.Name([country("AT"), state("Vienna")])),
        # list of x509.NameAttribute objects also works
        ([country("AT"), state("Vienna")], x509.Name([country("AT"), state("Vienna")])),
        ([], x509.Name([])),  # empty list yields empty Name
        (None, None),  # None yields no default subject
    ),
)
def test_ca_default_subject(settings: SettingsWrapper, value: Any, expected: x509.Name) -> None:
    """Test CA_DEFAULT_SUBJECT setting."""
    settings.CA_DEFAULT_SUBJECT = value
    assert model_settings.CA_DEFAULT_SUBJECT == expected


@pytest.mark.parametrize(
    "value,msg", (((("CN", ""),), r"<Name\(CN=\)>: CommonName must not be an empty value\."),)
)
def test_ca_default_subject_with_invalid_values(settings: SettingsWrapper, value: Any, msg: str) -> None:
    """Test the check for empty common names."""
    with assert_improperly_configured(msg):
        settings.CA_DEFAULT_SUBJECT = value


@pytest.mark.parametrize(
    "value,expected",
    (
        ([("CN", "example.com")], x509.Name([cn("example.com")])),
        ((("C", "AT"), ("CN", "example.com")), x509.Name([country("AT"), cn("example.com")])),
        ([country("AT"), ("CN", "example.com")], x509.Name([country("AT"), cn("example.com")])),
        (
            [country("AT"), (NameOID.COMMON_NAME, "example.com")],
            x509.Name([country("AT"), cn("example.com")]),
        ),
    ),
)
def test_ca_default_subject_with_deprecated_values(
    settings: SettingsWrapper, value: Any, expected: x509.Name
) -> None:
    """Test CA_DEFAULT_SUBJECT with deprecated lists."""
    msg = r"Support for two-element tuples as subject is deprecated and will be removed in django-ca 2\.2\."
    with assert_removed_in_220(msg):
        settings.CA_DEFAULT_SUBJECT = value
        assert model_settings.CA_DEFAULT_SUBJECT == expected


@pytest.mark.parametrize(
    "value,msg",
    (
        ([("invalid", "wrong")], "invalid: Invalid object identifier"),
        ([["one-element"]], r"Must be lists/tuples with two items, got 1\."),
        ([(True, "foo")], r"True: Must be a x509.ObjectIdentifier or str\."),
        ([("CN", True)], r"True: Item values must be strings\."),
        (["foo"], r"foo: Items must be a x509.NameAttribute, list or tuple\."),
        ((("C", "AT"), ("C", "DE")), r'<Name\(C=AT,C=DE\)>: Contains multiple "countryName" fields\.'),
    ),
)
def test_ca_default_subject_with_deprecated_invalid_values(
    settings: SettingsWrapper, value: Any, msg: str
) -> None:
    """Test invalid values in the deprecated format."""
    with assert_improperly_configured(msg):
        settings.CA_DEFAULT_SUBJECT = value


def test_ca_key_backend_is_not_configured(settings: SettingsWrapper) -> None:
    """Test that the default key backend is configured."""
    # Note: setting value to None (=removing the value) does not currently call settings_changed, so our
    # settings module is not reloaded.
    settings.CA_KEY_BACKENDS = {}
    assert model_settings.CA_KEY_BACKENDS == {
        "default": KeyBackendConfigurationModel(
            BACKEND="django_ca.key_backends.storages.StoragesBackend", OPTIONS={"storage_alias": "django-ca"}
        )
    }


def test_ca_ocsp_responder_certificate_renewal(settings: SettingsWrapper) -> None:
    """Test the CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL setting."""
    settings.CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL = 7200
    assert model_settings.CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL == timedelta(seconds=7200)


def test_ca_ocsp_responder_certificate_renewal_with_invalid_value(settings: SettingsWrapper) -> None:
    """Test the CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL setting with an invalid value."""
    with assert_improperly_configured(r"Input should be a valid timedelta"):
        settings.CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL = "600"


def test_ca_passwords(settings: SettingsWrapper) -> None:
    """Test type coercion and sanitization of keys."""
    settings.CA_PASSWORDS = {"AA:BB:CC": "secret-str", "01:23:45": b"secret-bytes"}
    # leading 0 in second serial are stripped, as they never end up in the database in the first place
    assert model_settings.CA_PASSWORDS == {"AABBCC": b"secret-str", "12345": b"secret-bytes"}


def test_ca_passwords_with_invalid_type(settings: SettingsWrapper) -> None:
    """Test setting an invalid password type."""
    with assert_improperly_configured(r"Input should be a valid bytes"):
        settings.CA_PASSWORDS = {"AA:BB:CC": None}


def test_ca_profiles_with_removed_profile(settings: SettingsWrapper) -> None:
    """Test removing a profile by setting it to None."""
    assert "client" in model_settings.CA_PROFILES  # initial assumption
    settings.CA_PROFILES = {"client": None}
    assert "client" not in model_settings.CA_PROFILES


def test_ca_profiles_update_description(settings: SettingsWrapper) -> None:
    """Test adding a profile in settings."""
    desc = "test description"
    settings.CA_PROFILES = {"client": {"description": desc}}
    assert model_settings.CA_PROFILES["client"].description == desc


@pytest.mark.parametrize(
    "subject,expected",
    (
        (False, False),
        ([], x509.Name([])),
        (tuple(), x509.Name([])),
        (x509.Name([country("AT")]), x509.Name([country("AT")])),
        ([{"oid": "C", "value": "AT"}], x509.Name([country("AT")])),
    ),
)
def test_ca_profiles_override_subject(settings: SettingsWrapper, subject: Any, expected: x509.Name) -> None:
    """Test overriding CA_DEFAULT_SUBJECT in CA_PROFILES."""
    assert model_settings.CA_DEFAULT_SUBJECT != expected  # would defeat purpose of test
    settings.CA_PROFILES = {"client": {"subject": subject}}
    assert model_settings.CA_PROFILES["client"].subject == expected


def test_ca_profiles_override_subject_with_deprecated_values(settings: SettingsWrapper) -> None:
    """Test overriding CA_DEFAULT_SUBJECT in CA_PROFILES with deprecated values."""
    settings.CA_PROFILES = {"client": {"subject": [{"oid": "C", "value": "AT"}]}}
    assert model_settings.CA_PROFILES["client"].subject == x509.Name([country("AT")])


@pytest.mark.parametrize(
    "value,msg",
    (
        ("foo", "Input should be a valid dictionary"),  # whole setting is invalid
        ({"client": {"subject": "foo"}}, r"Value error, foo: Must be a list or tuple\."),
        ({"client": {"subject": [True]}}, r"True: Items must be a x509.NameAttribute, list or tuple\."),
    ),
)
def test_ca_profiles_with_invalid_values(settings: SettingsWrapper, value: Any, msg: str) -> None:
    """Test invalid values in profiles."""
    with assert_improperly_configured(msg):
        settings.CA_PROFILES = value


def test_ca_use_celery(settings: SettingsWrapper) -> None:
    """Test CA_USE_CELERY setting."""
    settings.CA_USE_CELERY = False
    assert model_settings.CA_USE_CELERY is False
    settings.CA_USE_CELERY = True
    assert model_settings.CA_USE_CELERY is True

    settings.CA_USE_CELERY = None
    assert model_settings.CA_USE_CELERY is True  # because Celery is installed


def test_ca_use_celery_is_not_set(settings: SettingsWrapper) -> None:
    """Test CA_USE_CELERY if it is NOT set in settings."""
    # NOTE: deleting a setting does not currently trigger the settings_changed signal, so we trigger it
    # manually
    # pylint: disable=protected-access  # for settings.
    delattr(settings, "CA_USE_CELERY")
    setting_changed.send(sender=settings._wrapped.__class__, setting="CA_USE_CELERY", value=None, enter=True)
    assert model_settings.CA_USE_CELERY is True  # because Celery is installed

    # Trigger signal again just to be sure
    settings.CA_USE_CELERY = True
    setting_changed.send(sender=settings._wrapped.__class__, setting="CA_USE_CELERY", value=None, enter=False)


@pytest.mark.parametrize("value", (False, None))
def test_ca_use_celery_is_falsy_with_celery_not_installed(settings: SettingsWrapper, value: Any) -> None:
    """Test behavior for CA_USE_CELERY if celery is not installed."""
    with mock.patch.dict("sys.modules", celery=None):
        settings.CA_USE_CELERY = value
        assert model_settings.CA_USE_CELERY is False


def test_ca_use_celery_is_true_with_celery_not_installed(settings: SettingsWrapper) -> None:
    """Test that CA_USE_CELERY=True and a missing Celery installation throws an error."""
    # Setting sys.modules['celery'] (modules cache) to None will cause the next import of that module
    # to trigger an import error:
    #   https://medium.com/python-pandemonium/how-to-test-your-imports-1461c1113be1
    #   https://docs.python.org/3.8/reference/import.html#the-module-cache
    msg = r"Value error, CA_USE_CELERY set to True, but Celery is not installed"
    with mock.patch.dict("sys.modules", celery=None):
        with assert_improperly_configured(msg):
            settings.CA_USE_CELERY = True
