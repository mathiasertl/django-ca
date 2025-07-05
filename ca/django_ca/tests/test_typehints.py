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

"""Some minor tests for type hints."""

from typing import Any, get_args

from cryptography import x509

import pytest

from django_ca import constants, typehints
from django_ca.tests.test_constants import oid_sorter
from django_ca.typehints import CRYPTOGRAPHY_VERSION


def _oid_sorter(oid: x509.ObjectIdentifier) -> str:
    return oid.dotted_string


def _extension_type_sorter(extension_type: type[x509.ExtensionType]) -> str:
    if extension_type == x509.UnrecognizedExtension:
        return ""
    return extension_type.oid.dotted_string


def test_configurable_extension_keys() -> None:
    """Test that ConfigurableExtensionKeys matches ConfigurableExtensionType."""
    keys = get_args(typehints.ConfigurableExtensionKeys)
    expected = sorted((ext.oid for ext in get_args(typehints.ConfigurableExtensionType)), key=oid_sorter)
    actual = sorted((constants.CONFIGURABLE_EXTENSION_KEY_OIDS[v] for v in keys), key=oid_sorter)
    assert actual == expected


def test_end_entity_certificate_extension_keys() -> None:
    """Test EndEntityCertificateExtensionKeys matches EndEntityCertificateExtension."""
    configurable_keys, added_keys = get_args(typehints.EndEntityCertificateExtensionKeys)
    keys = get_args(configurable_keys) + get_args(added_keys)

    expected = sorted(
        (get_args(ext)[0].oid for ext in get_args(typehints.EndEntityCertificateExtension)), key=oid_sorter
    )
    actual = sorted((constants.END_ENTITY_CERTIFICATE_EXTENSION_KEY_OIDS[v] for v in keys), key=oid_sorter)
    if CRYPTOGRAPHY_VERSION < (45,):
        actual.remove(x509.ObjectIdentifier("2.5.29.16"))  # Remove PrivateKeyUsagePeriod
    assert actual == expected


@pytest.mark.parametrize(
    ("extension_types", "extensions"),
    (
        (typehints.ConfigurableExtensionType, typehints.ConfigurableExtension),
        (typehints.EndEntityCertificateExtensionType, typehints.EndEntityCertificateExtension),
        (typehints.CertificateExtensionType, typehints.CertificateExtension),
    ),
)
def test_extension_types_equality(extension_types: Any, extensions: Any) -> None:
    """Test that extension_types typehints match the full extension typehints."""
    assert sorted(get_args(extension_types), key=_extension_type_sorter) == sorted(
        list(get_args(ext)[0] for ext in get_args(extensions)), key=_extension_type_sorter
    )
