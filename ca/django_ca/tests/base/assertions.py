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

import io
import re
import typing
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone as tz
from typing import AnyStr, Optional, Union
from unittest.mock import Mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, x448, x25519
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtensionOID
from OpenSSL.crypto import FILETYPE_PEM, X509Store, X509StoreContext, load_certificate

from django.core.exceptions import ImproperlyConfigured
from django.core.management import CommandError

import pytest

from django_ca.conf import model_settings
from django_ca.constants import ReasonFlags
from django_ca.deprecation import RemovedInDjangoCA220Warning
from django_ca.key_backends.storages import UsePrivateKeyOptions
from django_ca.models import Certificate, CertificateAuthority, X509CertMixin
from django_ca.signals import post_create_ca, post_issue_cert, pre_create_ca, pre_sign_cert
from django_ca.tests.base.mocks import mock_signal
from django_ca.tests.base.utils import (
    authority_information_access,
    basic_constraints,
    cmd_e2e,
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
    assert actual.key_identifier == expected.key_identifier  # type: ignore[union-attr]


def assert_ca_properties(
    ca: CertificateAuthority,
    name: str,
    parent: Optional[CertificateAuthority] = None,
    private_key_type: type[CertificateIssuerPrivateKeyTypes] = rsa.RSAPrivateKey,
    acme_enabled: bool = False,
    acme_profile: Optional[str] = None,
    acme_requires_contact: bool = True,
    crl_number: str = '{"scope": {}}',
    password: Optional[bytes] = None,
) -> None:
    """Assert some basic properties of a CA."""
    parent_ca = parent or ca
    parent_serial = parent_ca.serial
    issuer = parent_ca.subject

    base_url = f"http://{model_settings.CA_DEFAULT_HOSTNAME}/django_ca/"
    assert ca.name == name
    assert ca.enabled is True
    assert ca.parent == parent
    assert ca.crl_number == crl_number

    # Test ACME properties
    assert ca.acme_enabled is acme_enabled
    assert ca.acme_profile == acme_profile or model_settings.CA_DEFAULT_PROFILE
    assert ca.acme_requires_contact is acme_requires_contact

    # Test certificate properties
    assert ca.issuer == issuer
    # TYPEHINT NOTE: We assume a StoragesBackend here

    assert isinstance(
        ca.key_backend.get_key(ca, UsePrivateKeyOptions(password=password)),  # type: ignore[attr-defined]
        private_key_type,
    )

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


def assert_certificate(
    cert: Union[Certificate, CertificateAuthority],
    subject: x509.Name,
    algorithm: type[hashes.HashAlgorithm] = hashes.SHA512,
    parent: Optional[CertificateAuthority] = None,
) -> None:
    """Assert certificate properties."""
    if isinstance(cert, Certificate):  # pragma: no cover  # pylint: disable=no-else-raise
        parent = cert.ca
        raise NotImplementedError("Remove no-cover pragma if this is caught.")
    elif parent is None:
        parent = cert
    else:
        parent = cert.parent
    assert cert.pub.loaded.version == x509.Version.v3
    assert cert.issuer == parent.subject  # type: ignore[union-attr]
    assert cert.subject == subject
    assert isinstance(cert.algorithm, algorithm)


@contextmanager
def assert_command_error(msg: str) -> Iterator[None]:
    """Context manager asserting that CommandError is raised.

    Parameters
    ----------
    msg : str
        The regex matching the exception message.
    """
    with pytest.raises(CommandError, match=msg):
        yield


@contextmanager
def assert_create_ca_signals(pre: bool = True, post: bool = True) -> Iterator[tuple[Mock, Mock]]:
    """Context manager asserting that the `pre_create_ca`/`post_create_ca` signals are (not) called."""
    with mock_signal(pre_create_ca) as pre_sig, mock_signal(post_create_ca) as post_sig:
        try:
            yield pre_sig, post_sig
        finally:
            assert pre_sig.called is pre
            assert post_sig.called is post


@contextmanager
def assert_create_cert_signals(pre: bool = True, post: bool = True) -> Iterator[tuple[Mock, Mock]]:
    """Context manager asserting that the `pre_create_cert`/`post_create_cert` signals are (not) called."""
    with mock_signal(pre_sign_cert) as pre_sig, mock_signal(post_issue_cert) as post_sig:
        try:
            yield pre_sig, post_sig
        finally:
            assert pre_sig.called is pre
            assert post_sig.called is post


def assert_crl(  # noqa: PLR0913
    crl: bytes,
    expected: Optional[typing.Sequence[X509CertMixin]] = None,
    signer: Optional[CertificateAuthority] = None,
    expires: int = 86400,
    algorithm: Optional[hashes.HashAlgorithm] = None,
    encoding: Encoding = Encoding.PEM,
    idp: Optional["x509.Extension[x509.IssuingDistributionPoint]"] = None,
    extensions: Optional[list["x509.Extension[x509.ExtensionType]"]] = None,
    crl_number: int = 0,
    entry_extensions: Optional[tuple[list[x509.Extension[x509.ExtensionType]]]] = None,
    last_update: Optional[datetime] = None,
) -> None:
    """Test the given CRL.

    Parameters
    ----------
    crl : bytes
        The raw CRL
    expected : list
    signer
    expires
    algorithm
    encoding
    idp
    extensions
    crl_number
    """
    expected = expected or []
    signer = signer or CertificateAuthority.objects.get(name="child")
    extensions = extensions or []
    now = datetime.now(tz=tz.utc)
    expires_timestamp = (now + timedelta(seconds=expires)).replace(microsecond=0)

    if idp is not None:  # pragma: no branch
        extensions.append(idp)
    if last_update is None:
        last_update = now.replace(microsecond=0)
    extensions.append(signer.get_authority_key_identifier_extension())
    extensions.append(
        x509.Extension(
            value=x509.CRLNumber(crl_number=crl_number), critical=False, oid=ExtensionOID.CRL_NUMBER
        )
    )

    if encoding == Encoding.PEM:
        parsed_crl = x509.load_pem_x509_crl(crl)
    else:
        parsed_crl = x509.load_der_x509_crl(crl)
    if algorithm is None:
        algorithm = signer.algorithm

    public_key = signer.pub.loaded.public_key()
    if isinstance(public_key, (x448.X448PublicKey, x25519.X25519PublicKey)):  # pragma: no cover
        raise TypeError()  # just to make mypy happy

    assert isinstance(parsed_crl.signature_hash_algorithm, type(algorithm))
    assert parsed_crl.is_signature_valid(public_key) is True
    assert parsed_crl.issuer == signer.pub.loaded.subject
    assert parsed_crl.last_update_utc == last_update
    assert parsed_crl.next_update_utc == expires_timestamp
    assert list(parsed_crl.extensions) == extensions

    entries = {e.serial_number: e for e in parsed_crl}
    assert sorted(entries) == sorted(c.pub.loaded.serial_number for c in expected)
    for i, entry in enumerate(entries.values()):
        if entry_extensions:
            assert list(entry.extensions) == entry_extensions[i]
        else:
            assert not list(entry.extensions)


def assert_e2e_command_error(
    cmd: typing.Sequence[str],
    stdout: Union[str, bytes, "re.Pattern[AnyStr]"] = "",
    stderr: Union[str, bytes, "re.Pattern[AnyStr]"] = "",
) -> None:
    """Assert that the passed command raises a CommandError with the given message."""
    if isinstance(stdout, str):  # pragma: no cover
        stdout = "CommandError: " + stdout + "\n"
    elif isinstance(stdout, bytes):  # pragma: no cover
        stdout = b"CommandError: " + stdout + b"\n"
    assert_e2e_error(cmd, stdout=stdout, stderr=stderr, code=1)


def assert_e2e_error(
    cmd: typing.Sequence[str],
    stdout: Union[str, bytes, "re.Pattern[AnyStr]"] = "",
    stderr: Union[str, bytes, "re.Pattern[AnyStr]"] = "",
    code: int = 2,
) -> None:
    """Assert an error was through in an e2e command."""
    if isinstance(stdout, str) or (isinstance(stdout, re.Pattern) and isinstance(stdout.pattern, str)):
        actual_stdout = io.StringIO()
    else:
        actual_stdout = io.BytesIO()  # type: ignore[assignment]

    if isinstance(stderr, str) or (isinstance(stderr, re.Pattern) and isinstance(stderr.pattern, str)):
        actual_stderr = io.StringIO()
    else:
        actual_stderr = io.BytesIO()  # type: ignore[assignment]

    with assert_system_exit(code):
        cmd_e2e(cmd, stdout=actual_stdout, stderr=actual_stderr)

    if isinstance(stdout, (str, bytes)):
        assert stdout == actual_stdout.getvalue()
    elif isinstance(stdout.pattern, str):  # pragma: no cover
        assert stdout.search(actual_stdout.getvalue())
    else:  # pragma: no cover
        raise NotImplementedError

    if isinstance(stderr, (str, bytes)):
        assert stderr == actual_stderr.getvalue()
    elif isinstance(stderr.pattern, str):
        assert stderr.search(actual_stderr.getvalue())
    else:  # pragma: no cover
        raise NotImplementedError


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
def assert_improperly_configured(msg: str) -> Iterator[None]:
    """Shortcut for testing that the code raises ImproperlyConfigured with the given message."""
    with pytest.raises(ImproperlyConfigured, match=msg):
        yield


def assert_post_issue_cert(post: Mock, cert: Certificate) -> None:
    """Assert that the post_issue_cert signal was called with the expected certificate."""
    post.assert_called_once_with(cert=cert, signal=post_issue_cert, sender=Certificate)


def assert_revoked(
    cert: X509CertMixin, reason: Optional[str] = None, compromised: Optional[datetime] = None
) -> None:
    """Assert that the certificate is now revoked."""
    if isinstance(cert, CertificateAuthority):
        cert = CertificateAuthority.objects.get(serial=cert.serial)
    else:
        cert = Certificate.objects.get(serial=cert.serial)

    assert cert.revoked
    assert cert.compromised == compromised

    if reason is None:
        assert cert.revoked_reason == ReasonFlags.unspecified.name
    else:
        assert cert.revoked_reason == reason


def assert_signature(
    chain: Iterable[CertificateAuthority], cert: Union[Certificate, CertificateAuthority]
) -> None:
    """Assert that `cert` is properly signed by `chain`.

    .. seealso:: http://stackoverflow.com/questions/30700348
    """
    store = X509Store()

    # set the time of the OpenSSL context - freezegun doesn't work, because timestamp comes from OpenSSL
    now = datetime.now(tz=tz.utc).replace(tzinfo=None)
    store.set_time(now)

    for elem in chain:
        ca = load_certificate(FILETYPE_PEM, elem.pub.pem.encode())
        store.add_cert(ca)

        # Verify that the CA itself is valid
        store_ctx = X509StoreContext(store, ca)
        assert store_ctx.verify_certificate() is None  # type: ignore[func-returns-value]

    loaded_cert = load_certificate(FILETYPE_PEM, cert.pub.pem.encode())
    store_ctx = X509StoreContext(store, loaded_cert)
    assert store_ctx.verify_certificate() is None  # type: ignore[func-returns-value]


@contextmanager
def assert_system_exit(code: int) -> Iterator[None]:
    """Assert that SystemExit is raised."""
    with pytest.raises(SystemExit, match=rf"^{code}$") as excm:
        yield
    assert excm.value.args == (code,)


@contextmanager
def assert_removed_in_220(match: Optional[Union[str, "re.Pattern[str]"]] = None) -> Iterator[None]:
    """Assert that a ``RemovedInDjangoCA200Warning`` is emitted."""
    with pytest.warns(RemovedInDjangoCA220Warning, match=match):
        yield
