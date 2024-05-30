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

import pytest

from django_ca import constants, typehints


def test_configurable_extension_keys() -> None:
    """Test that ConfigurableExtensionKeys matches ConfigurableExtensionType."""
    keys = get_args(typehints.ConfigurableExtensionKeys)
    expected = tuple(ext.oid for ext in get_args(typehints.ConfigurableExtensionType))
    assert tuple(constants.CONFIGURABLE_EXTENSION_KEY_OIDS[v] for v in keys) == expected


def test_end_entity_certificate_extension_keys() -> None:
    """Test EndEntityCertificateExtensionKeys matches EndEntityCertificateExtension."""
    configurable_keys, added_keys = get_args(typehints.EndEntityCertificateExtensionKeys)
    keys = get_args(configurable_keys) + get_args(added_keys)

    expected = tuple(get_args(ext)[0].oid for ext in get_args(typehints.EndEntityCertificateExtension))
    assert tuple(constants.END_ENTITY_CERTIFICATE_EXTENSION_KEY_OIDS[v] for v in keys) == expected


@pytest.mark.parametrize(
    "extension_types,extensions",
    (
        (typehints.ConfigurableExtensionType, typehints.ConfigurableExtension),
        (typehints.EndEntityCertificateExtensionType, typehints.EndEntityCertificateExtension),
        (typehints.CertificateExtensionType, typehints.CertificateExtension),
    ),
)
def test_extension_types_equality(extension_types: Any, extensions: Any) -> None:
    """Test that extension_types typehints match the full extension typehints."""
    assert get_args(extension_types) == tuple(get_args(ext)[0] for ext in get_args(extensions))
