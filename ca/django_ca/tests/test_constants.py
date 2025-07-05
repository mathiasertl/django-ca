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

"""Some sanity tests for constants."""

from typing import Any, TypeVar, get_args

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from django_ca import constants, typehints
from django_ca.constants import CRYPTOGRAPHY_VERSION, ExtensionOID
from django_ca.typehints import GeneralNames, HashAlgorithms


def oid_sorter(oid: x509.ObjectIdentifier) -> str:
    """Helper to sort OIDs (to ease list equality checking)."""
    return oid.dotted_string


SuperclassTypeVar = TypeVar("SuperclassTypeVar", bound=type[Any])
KNOWN_EXTENSION_OIDS = sorted(
    filter(
        lambda attr: isinstance(attr, x509.ObjectIdentifier),
        [getattr(ExtensionOID, attr) for attr in dir(ExtensionOID)],
    ),
    key=oid_sorter,
)
KNOWN_EXTENDED_KEY_USAGE_OIDS = sorted(
    filter(
        lambda attr: isinstance(attr, x509.ObjectIdentifier),
        [getattr(constants.ExtendedKeyUsageOID, attr) for attr in dir(constants.ExtendedKeyUsageOID)],
    ),
    key=oid_sorter,
)


def get_subclasses(cls: type[SuperclassTypeVar]) -> set[type[SuperclassTypeVar]]:
    """Recursively get a list of subclasses.

    .. seealso:: https://stackoverflow.com/a/3862957
    """
    return set(cls.__subclasses__()).union([s for c in cls.__subclasses__() for s in get_subclasses(c)])


def test_certificate_extension_keys_typehints() -> None:
    """Test that END_ENTITY_CERTIFICATE_EXTENSION_KEYS has matching keys and values."""
    configurable, end_entity, added = get_args(typehints.CertificateExtensionKeys)
    expected = sorted([*get_args(configurable), *get_args(end_entity), *get_args(added)])

    # "unknown" does not exist in constants, as there is no OID to map to, obviously.
    expected.remove("unknown")

    # Values of END_ENTITY_CERTIFICATE_EXTENSION_KEYS match exactly the Literal -> did not forget any value.
    assert sorted(constants.CERTIFICATE_EXTENSION_KEYS.values()) == expected

    # check that all keys (=Object identifiers) occur in ConfigurableExtensionType
    extension_types = [
        et for et in get_args(typehints.CertificateExtensionType) if et != x509.UnrecognizedExtension
    ]
    expected = sorted((ext.oid for ext in extension_types), key=oid_sorter)
    actual = sorted(constants.CERTIFICATE_EXTENSION_KEYS, key=oid_sorter)
    if CRYPTOGRAPHY_VERSION < (45,):
        actual.remove(x509.ObjectIdentifier("2.5.29.16"))  # Remove PrivateKeyUsagePeriod
    assert actual == expected


def test_configurable_extension_keys_typehints() -> None:
    """Test that CONFIGURABLE_EXTENSION_KEYS has matching keys and values."""
    assert sorted(constants.CONFIGURABLE_EXTENSION_KEYS.values()) == sorted(
        get_args(typehints.ConfigurableExtensionKeys)
    )

    # check that all keys (=Object identifiers) occur in ConfigurableExtensionType
    expected = sorted((ext.oid for ext in get_args(typehints.ConfigurableExtensionType)), key=oid_sorter)
    actual = sorted(constants.CONFIGURABLE_EXTENSION_KEYS, key=oid_sorter)
    assert actual == expected


def test_elliptic_curves() -> None:
    """Test that ``utils.ELLIPTIC_CURVE_TYPES`` covers all known elliptic curves.

    The point of this test is that it fails if a new cryptography version adds new curves, thus allowing
    us to detect if the constant becomes out of date.
    """
    # MYPY NOTE: mypy does not allow passing abstract classes for type variables, see
    #            https://github.com/python/mypy/issues/5374#issuecomment-436638471
    subclasses = get_subclasses(ec.EllipticCurve)  # type: ignore[type-var, type-abstract]
    assert constants.ELLIPTIC_CURVE_TYPES == {e.name: e for e in subclasses}


def test_end_entity_certificate_extension_keys_typehints() -> None:
    """Test that END_ENTITY_CERTIFICATE_EXTENSION_KEYS has matching keys and values."""
    configurable_keys, added_keys = get_args(typehints.EndEntityCertificateExtensionKeys)
    expected = sorted(get_args(configurable_keys) + get_args(added_keys))

    # Values of END_ENTITY_CERTIFICATE_EXTENSION_KEYS match exactly the Literal -> did not forget any value.
    assert sorted(constants.END_ENTITY_CERTIFICATE_EXTENSION_KEYS.values()) == expected

    # check that all keys (=Object identifiers) occur in ConfigurableExtensionType
    expected = sorted(
        (ext.oid for ext in get_args(typehints.EndEntityCertificateExtensionType)), key=oid_sorter
    )
    actual = sorted(constants.END_ENTITY_CERTIFICATE_EXTENSION_KEYS, key=oid_sorter)

    if CRYPTOGRAPHY_VERSION < (45,):
        actual.remove(x509.ObjectIdentifier("2.5.29.16"))  # Add PrivateKeyUsagePeriod

    assert actual == expected


def test_extended_key_usage_human_readable_names() -> None:
    """Test completeness of the ``EXTENDED_KEY_USAGE_HUMAN_READABLE_NAMES`` constant."""
    assert KNOWN_EXTENDED_KEY_USAGE_OIDS == sorted(
        constants.EXTENDED_KEY_USAGE_HUMAN_READABLE_NAMES, key=oid_sorter
    )


def test_extended_key_usage_oids() -> None:
    """Test ExtendedKeyUsageOID for duplicates."""
    assert KNOWN_EXTENDED_KEY_USAGE_OIDS == sorted(set(KNOWN_EXTENDED_KEY_USAGE_OIDS), key=oid_sorter)


def test_extended_key_usage_names() -> None:
    """Test completeness of ``EXTENDED_KEY_USAGE_NAMES`` constant."""
    assert KNOWN_EXTENDED_KEY_USAGE_OIDS == sorted(constants.EXTENDED_KEY_USAGE_NAMES, key=oid_sorter)


def test_extension_critical_help() -> None:
    """Test completeness of EXTENSION_CRITICAL_HELP."""
    assert KNOWN_EXTENSION_OIDS == sorted(constants.EXTENSION_CRITICAL_HELP, key=oid_sorter)


def test_extension_default_critical() -> None:
    """Test completeness of EXTENSION_DEFAULT_CRITICAL."""
    known_oids = [oid for oid in KNOWN_EXTENSION_OIDS if oid != ExtensionOID.MS_CERTIFICATE_TEMPLATE]
    assert sorted(known_oids, key=oid_sorter) == sorted(constants.EXTENSION_DEFAULT_CRITICAL, key=oid_sorter)


def test_extension_keys() -> None:
    """Test completeness of the ``KNOWN_EXTENSION_OIDS`` constant."""
    assert KNOWN_EXTENSION_OIDS == sorted(constants.EXTENSION_KEYS, key=oid_sorter)


def test_extension_names_completeness() -> None:
    """Test completeness of EXTENSION_NAMES."""
    assert KNOWN_EXTENSION_OIDS == sorted(constants.EXTENSION_NAMES, key=oid_sorter)


def test_general_name_types() -> None:
    """Test :py:attr:`~django_ca.constants.GENERAL_NAME_TYPES` for completeness."""
    subclasses = get_subclasses(x509.GeneralName)  # type: ignore[type-var, type-abstract]
    assert len(constants.GENERAL_NAME_TYPES) == len(subclasses)
    assert set(constants.GENERAL_NAME_TYPES.values()) == set(subclasses)

    # Make sure that keys match the typehint exactly
    assert sorted(constants.GENERAL_NAME_TYPES) == sorted(get_args(GeneralNames))


def test_hash_algorithm_names() -> None:
    """Test :py:attr:`~django_ca.constants.GENERAL_NAME_TYPES` for completeness."""
    subclasses = get_subclasses(hashes.HashAlgorithm)  # type: ignore[type-var, type-abstract]

    # filter out hash algorithms that are not supported right now due to them having a digest size as
    # parameter
    excluded_algorithms = (
        hashes.SHAKE128,
        hashes.SHAKE256,
        hashes.BLAKE2b,
        hashes.BLAKE2s,
        hashes.SM3,
        hashes.SHA512_224,
        hashes.SHA512_256,
    )
    subclasses = set(sc for sc in subclasses if sc not in excluded_algorithms)

    # These are deliberately not supported anymore:
    if hasattr(hashes, "MD5"):
        subclasses.remove(hashes.MD5)
    if hasattr(hashes, "SHA1"):
        subclasses.remove(hashes.SHA1)

    assert len(constants.HASH_ALGORITHM_NAMES) == len(subclasses)

    # Make sure that keys match the typehint exactly
    assert sorted(constants.HASH_ALGORITHM_NAMES.values()) == sorted(get_args(HashAlgorithms))


def test_name_oid_names_completeness() -> None:
    """Test that we support all NameOID instances."""
    known_oids = [v for v in vars(x509.NameOID).values() if isinstance(v, x509.ObjectIdentifier)]
    assert sorted(known_oids, key=oid_sorter) == sorted(constants.NAME_OID_NAMES, key=oid_sorter)


def test_reason_flags_completeness() -> None:
    """Test that our list completely mirrors the cryptography list."""
    actual = sorted([(k, v.value) for k, v in constants.ReasonFlags.__members__.items()])
    expected = sorted([(k, v.value) for k, v in x509.ReasonFlags.__members__.items()])
    assert actual == expected
