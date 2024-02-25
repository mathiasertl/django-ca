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

""":py:mod:`django_ca.tests.base.assertions` collects assertions used throughout the entire test suite."""

import re
import typing
from contextlib import contextmanager
from typing import Iterable, Iterator, Optional, Tuple, Type, Union
from unittest.mock import Mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.x509.oid import ExtensionOID

import pytest

from django_ca import ca_settings
from django_ca.deprecation import RemovedInDjangoCA200Warning
from django_ca.models import Certificate, CertificateAuthority, X509CertMixin
from django_ca.signals import post_create_ca, pre_create_ca
from django_ca.tests.base.mocks import mock_signal
from django_ca.tests.base.utils import (
    authority_information_access,
    basic_constraints,
    crl_distribution_points,
    distribution_point,
    uri,
)


def assert_authority_key_identifier(issuer: CertificateAuthority, cert: X509CertMixin) -> None:
    """Assert the AuthorityKeyIdentifier extension of `issuer`.

    This assertion tests that :py:class:`~cg:cryptography.x509.AuthorityKeyIdentifier` extension of `cert`
    matches the :py:class:`~cg:cryptography.x509.SubjectKeyIdentifier` extension of `issuer`.
    """
    actual = cert.extensions[ExtensionOID.AUTHORITY_KEY_IDENTIFIER].value
    expected = issuer.extensions[ExtensionOID.SUBJECT_KEY_IDENTIFIER].value
    assert actual.key_identifier == expected.key_identifier


def assert_ca_properties(
    ca: CertificateAuthority,
    name: str,
    subject: x509.Name,
    parent: Optional[CertificateAuthority] = None,
    private_key_type: Type[CertificateIssuerPrivateKeyTypes] = rsa.RSAPrivateKey,
    algorithm: Type[hashes.HashAlgorithm] = hashes.SHA512,
    acme_enabled: bool = False,
    acme_profile: Optional[str] = None,
    acme_requires_contact: bool = True,
) -> None:
    """Assert some basic properties of a CA."""
    parent_ca = parent or ca
    parent_serial = parent_ca.serial
    issuer = parent_ca.subject

    base_url = f"http://{ca_settings.CA_DEFAULT_HOSTNAME}/django_ca/"
    assert ca.name == name
    assert ca.enabled is True
    assert ca.parent == parent
    assert ca.crl_number == '{"scope": {}}'

    # Test ACME properties
    assert ca.acme_enabled is acme_enabled
    assert ca.acme_profile == acme_profile or ca_settings.CA_DEFAULT_PROFILE
    assert ca.acme_requires_contact is acme_requires_contact

    # Test certificate properties
    assert ca.issuer == issuer
    assert ca.subject == subject
    assert isinstance(ca.get_key_backend().key, private_key_type)
    assert isinstance(ca.algorithm, algorithm)

    # Test AuthorityKeyIdentifier extension
    assert_authority_key_identifier(parent_ca, ca)

    # Test the BasicConstraints extension
    basic_constraints_ext = typing.cast(
        x509.Extension[x509.BasicConstraints], ca.extensions[ExtensionOID.BASIC_CONSTRAINTS]
    )
    assert basic_constraints_ext.critical is True
    assert basic_constraints_ext.value.ca is True

    # Test default signing extensions
    assert ca.sign_authority_information_access == authority_information_access(
        ocsp=[uri(f"{base_url}ocsp/{ca.serial}/cert/")],
        ca_issuers=[uri(f"{base_url}issuer/{parent_serial}.der")],
    )
    assert ca.sign_certificate_policies is None
    assert ca.sign_crl_distribution_points == crl_distribution_points(
        distribution_point([uri(f"{base_url}crl/{ca.serial}/")])
    )
    assert ca.sign_issuer_alternative_name is None


@contextmanager
def assert_create_ca_signals(pre: bool = True, post: bool = True) -> Iterator[Tuple[Mock, Mock]]:
    """Context manager asserting that the `pre_create_ca` and `post_create_ca` signals are (not) called."""
    with mock_signal(pre_create_ca) as pre_sig, mock_signal(post_create_ca) as post_sig:
        try:
            yield pre_sig, post_sig
        finally:
            assert pre_sig.called is pre
            assert post_sig.called is post


def assert_extensions(
    cert: Union[X509CertMixin, x509.Certificate],
    extensions: Iterable[x509.Extension[x509.ExtensionType]],
    signer: Optional[CertificateAuthority] = None,
    expect_defaults: bool = True,
) -> None:
    """Assert that `cert` has the given extensions."""
    # temporary fast check
    for ext in extensions:
        assert isinstance(ext, x509.Extension)

    expected = {e.oid: e for e in extensions}

    if isinstance(cert, Certificate):
        pubkey = cert.pub.loaded.public_key()
        actual = cert.extensions
        signer = cert.ca
    elif isinstance(cert, CertificateAuthority):
        pubkey = cert.pub.loaded.public_key()
        actual = cert.extensions

        if cert.parent is None:  # root CA
            signer = cert
        else:  # intermediate CA
            signer = cert.parent
    elif isinstance(cert, x509.Certificate):  # cg cert
        pubkey = cert.public_key()
        actual = {e.oid: e for e in cert.extensions}
    else:  # pragma: no cover
        raise ValueError("cert must be Certificate(Authority) or x509.Certificate)")

    if expect_defaults is True:
        if isinstance(cert, Certificate):
            expected.setdefault(ExtensionOID.BASIC_CONSTRAINTS, basic_constraints(ca=False))
        if signer is not None:  # pragma: no branch
            expected.setdefault(
                ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
                signer.get_authority_key_identifier_extension(),
            )

            if isinstance(cert, Certificate) and signer.sign_crl_distribution_points:
                expected.setdefault(ExtensionOID.CRL_DISTRIBUTION_POINTS, signer.sign_crl_distribution_points)

            if isinstance(cert, Certificate) and signer.sign_authority_information_access:
                expected.setdefault(
                    ExtensionOID.AUTHORITY_INFORMATION_ACCESS, signer.sign_authority_information_access
                )

        ski = x509.SubjectKeyIdentifier.from_public_key(pubkey)
        expected.setdefault(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            x509.Extension(oid=ExtensionOID.SUBJECT_KEY_IDENTIFIER, critical=False, value=ski),
        )

    # Diff output is bad for dicts, so we sort this based on dotted string to get better output
    actual_tuple = sorted(actual.items(), key=lambda t: t[0].dotted_string)
    expected_tuple = sorted(expected.items(), key=lambda t: t[0].dotted_string)
    assert actual_tuple == expected_tuple


@contextmanager
def assert_removed_in_200(match: Optional[Union[str, "re.Pattern[str]"]] = None) -> Iterator[None]:
    """Assert that a ``RemovedInDjangoCA200Warning`` is emitted."""
    with pytest.warns(RemovedInDjangoCA200Warning, match=match):
        yield
