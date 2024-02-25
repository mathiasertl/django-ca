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
from typing import Iterator, Optional, Tuple, Union
from unittest.mock import Mock

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

import pytest

from django_ca import ca_settings
from django_ca.deprecation import RemovedInDjangoCA200Warning
from django_ca.models import CertificateAuthority, X509CertMixin
from django_ca.signals import post_create_ca, pre_create_ca
from django_ca.tests.base.mocks import mock_signal
from django_ca.tests.base.utils import (
    authority_information_access,
    crl_distribution_points,
    distribution_point,
    uri,
)


def assert_authority_key_identifier(self, issuer: CertificateAuthority, cert: X509CertMixin) -> None:
    """Assert the AuthorityKeyIdentifier extension of `issuer`.

    This assertion tests that :py:class:`~cg:cryptography.x509.AuthorityKeyIdentifier` extension of `cert`
    matches the :py:class:`~cg:cryptography.x509.SubjectKeyIdentifier` extension of `issuer`.
    """
    actual = cert.extensions[ExtensionOID.AUTHORITY_KEY_IDENTIFIER].value
    expected = issuer.extensions[ExtensionOID.SUBJECT_KEY_IDENTIFIER].value
    assert actual.key_identifier == expected.key_identifier


def assert_certificate_authority_properties(
    ca: CertificateAuthority, name: str, subject: x509.Name, parent: Optional[CertificateAuthority] = None
) -> None:
    """Assert some basic properties of a CA."""
    parent_ca = parent or ca
    parent_serial = parent_ca.serial
    issuer = parent_ca.subject

    base_url = f"http://{ca_settings.CA_DEFAULT_HOSTNAME}/django_ca/"
    assert ca.name == name
    assert ca.issuer == issuer
    assert ca.subject == subject
    assert ca.enabled is True
    assert ca.parent == parent
    assert ca.crl_number == '{"scope": {}}'

    # Test AuthorityKeyIdentifier extension
    assert_authority_key_identifier(parent_ca, ca)

    # Test the BasicConstraints extension
    basic_constraints_ext = typing.cast(
        x509.Extension[x509.BasicConstraints], ca.extensions[ExtensionOID.BASIC_CONSTRAINTS].value
    )
    assert basic_constraints_ext.critical is True
    assert basic_constraints_ext.value.ca is False

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


@contextmanager
def assert_removed_in_200(match: Optional[Union[str, "re.Pattern[str]"]] = None) -> Iterator[None]:
    """Assert that a ``RemovedInDjangoCA200Warning`` is emitted."""
    with pytest.warns(RemovedInDjangoCA200Warning, match=match):
        yield
