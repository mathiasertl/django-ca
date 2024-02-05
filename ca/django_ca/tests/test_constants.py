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

import typing
from typing import Any, Set, Type

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID

from django.test import TestCase

from django_ca import constants
from django_ca.typehints import GeneralNames, HashAlgorithms

SuperclassTypeVar = typing.TypeVar("SuperclassTypeVar", bound=Type[Any])
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


def get_subclasses(cls: Type[SuperclassTypeVar]) -> Set[Type[SuperclassTypeVar]]:
    """Recursively get a list of subclasses.

    .. seealso:: https://stackoverflow.com/a/3862957
    """
    return set(cls.__subclasses__()).union([s for c in cls.__subclasses__() for s in get_subclasses(c)])


def test_general_name_types() -> None:
    """Test :py:attr:`~django_ca.constants.GENERAL_NAME_TYPES` for completeness."""
    subclasses = get_subclasses(x509.GeneralName)  # type: ignore[type-var, type-abstract]
    assert len(constants.GENERAL_NAME_TYPES) == len(subclasses)
    assert set(constants.GENERAL_NAME_TYPES.values()) == set(subclasses)

    # Make sure that keys match the typehint exactly
    assert sorted(constants.GENERAL_NAME_TYPES) == sorted(typing.get_args(GeneralNames))


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
    assert sorted(constants.HASH_ALGORITHM_NAMES.values()) == sorted(typing.get_args(HashAlgorithms))


class ReasonFlagsTestCase(TestCase):
    """Test reason flags."""

    def test_completeness(self) -> None:
        """Test that our list completely mirrors the cryptography list."""
        self.assertEqual(
            list(sorted([(k, v.value) for k, v in constants.ReasonFlags.__members__.items()])),
            list(sorted([(k, v.value) for k, v in x509.ReasonFlags.__members__.items()])),
        )


class CompletenessTestCase(TestCase):
    """Test for completeness of various constants."""

    def test_elliptic_curves(self) -> None:
        """Test that ``utils.ELLIPTIC_CURVE_TYPES`` covers all known elliptic curves.

        The point of this test is that it fails if a new cryptography version adds new curves, thus allowing
        us to detect if the constant becomes out of date.
        """
        # MYPY NOTE: mypy does not allow passing abstract classes for type variables, see
        #            https://github.com/python/mypy/issues/5374#issuecomment-436638471
        subclasses = get_subclasses(ec.EllipticCurve)  # type: ignore[type-var, type-abstract]
        self.assertEqual(len(constants.ELLIPTIC_CURVE_TYPES), len(subclasses))
        self.assertEqual(constants.ELLIPTIC_CURVE_TYPES, {e.name: e for e in subclasses})

    def test_extended_key_usage_oids(self) -> None:
        """Test ExtendedKeyUsageOID for duplicates."""
        self.assertCountEqual(KNOWN_EXTENDED_KEY_USAGE_OIDS, list(set(KNOWN_EXTENDED_KEY_USAGE_OIDS)))

    def test_extended_key_usage_names(self) -> None:
        """Test completeness of ``EXTENDED_KEY_USAGE_NAMES`` constant."""
        self.assertCountEqual(KNOWN_EXTENDED_KEY_USAGE_OIDS, constants.EXTENDED_KEY_USAGE_NAMES.keys())

    def test_extended_key_usage_human_readable_names(self) -> None:
        """Test completeness of the ``EXTENDED_KEY_USAGE_HUMAN_READABLE_NAMES`` constant."""
        self.assertCountEqual(
            KNOWN_EXTENDED_KEY_USAGE_OIDS, constants.EXTENDED_KEY_USAGE_HUMAN_READABLE_NAMES.keys()
        )

    def test_extension_keys(self) -> None:
        """Test completeness of the ``KNOWN_EXTENSION_OIDS`` constant."""
        self.assertCountEqual(KNOWN_EXTENSION_OIDS, constants.EXTENSION_KEYS.keys())

    def test_nameoid(self) -> None:
        """Test that we support all NameOID instances."""
        known_oids = [v for v in vars(x509.NameOID).values() if isinstance(v, x509.ObjectIdentifier)]
        organization_id = x509.ObjectIdentifier("2.5.4.97")
        if organization_id not in known_oids:  # pragma: only cryptography<42.0
            known_oids.append(organization_id)
        self.assertCountEqual(known_oids, list(constants.NAME_OID_NAMES.keys()))

    def test_oid_to_extension_names(self) -> None:
        """Test completeness of EXTENSION_NAMES."""
        self.assertCountEqual(KNOWN_EXTENSION_OIDS, constants.EXTENSION_NAMES.keys())

    def test_oid_default_critical(self) -> None:
        """Test completeness of EXTENSION_DEFAULT_CRITICAL."""
        known_oids = [oid for oid in KNOWN_EXTENSION_OIDS if oid != ExtensionOID.MS_CERTIFICATE_TEMPLATE]
        self.assertCountEqual(known_oids, constants.EXTENSION_DEFAULT_CRITICAL.keys())

    def test_oid_critical_help(self) -> None:
        """Test completeness of EXTENSION_CRITICAL_HELP."""
        self.assertCountEqual(KNOWN_EXTENSION_OIDS, constants.EXTENSION_CRITICAL_HELP.keys())
