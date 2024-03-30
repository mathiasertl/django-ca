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

"""Utility functions used in testing."""

import doctest
import importlib
import inspect
import ipaddress
import os
import re
import shutil
import tempfile
import typing
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import datetime
from io import BytesIO, StringIO
from typing import Any, Dict, List, Optional, Tuple, Union
from unittest import mock

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from django.conf import settings
from django.core.management import ManagementUtility, call_command
from django.test import override_settings
from django.utils.crypto import get_random_string

from django_ca.models import CertificateAuthority, X509CertMixin
from django_ca.profiles import profiles
from django_ca.tests.base.constants import CERT_DATA, FIXTURES_DIR


def authority_information_access(
    ca_issuers: Optional[Iterable[x509.GeneralName]] = None,
    ocsp: Optional[Iterable[x509.GeneralName]] = None,
    critical: bool = False,
) -> x509.Extension[x509.AuthorityInformationAccess]:
    """Shortcut for getting a AuthorityInformationAccess extension."""
    access_descriptions = []

    # NOTE: OCSP is first because OID is lexicographically smaller
    if ocsp is not None:  # pragma: no branch
        access_descriptions += [
            x509.AccessDescription(access_method=AuthorityInformationAccessOID.OCSP, access_location=name)
            for name in ocsp
        ]
    if ca_issuers is not None:  # pragma: no branch
        access_descriptions += [
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.CA_ISSUERS, access_location=issuer
            )
            for issuer in ca_issuers
        ]

    value = x509.AuthorityInformationAccess(access_descriptions)

    return x509.Extension(oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS, critical=critical, value=value)


def basic_constraints(
    ca: bool = False, path_length: Optional[int] = None, critical: bool = True
) -> x509.Extension[x509.BasicConstraints]:
    """Shortcut for getting a BasicConstraints extension."""
    return x509.Extension(
        oid=ExtensionOID.BASIC_CONSTRAINTS,
        critical=critical,
        value=x509.BasicConstraints(ca=ca, path_length=path_length),
    )


def certificate_policies(
    *policies: x509.PolicyInformation, critical: bool = False
) -> x509.Extension[x509.CertificatePolicies]:
    """Shortcut for getting a Certificate Policy extension."""
    return x509.Extension(
        oid=ExtensionOID.CERTIFICATE_POLICIES, critical=critical, value=x509.CertificatePolicies(policies)
    )


@typing.overload
def cmd(*args: Any, stdout: BytesIO, stderr: BytesIO, **kwargs: Any) -> Tuple[bytes, bytes]: ...


@typing.overload
def cmd(
    *args: Any, stdout: BytesIO, stderr: Optional[StringIO] = None, **kwargs: Any
) -> Tuple[bytes, str]: ...


@typing.overload
def cmd(
    *args: Any, stdout: Optional[StringIO] = None, stderr: BytesIO, **kwargs: Any
) -> Tuple[str, bytes]: ...


@typing.overload
def cmd(
    *args: Any, stdout: Optional[StringIO] = None, stderr: Optional[StringIO] = None, **kwargs: Any
) -> Tuple[str, str]: ...


def cmd(
    *args: Any,
    stdout: Optional[Union[StringIO, BytesIO]] = None,
    stderr: Optional[Union[StringIO, BytesIO]] = None,
    **kwargs: Any,
) -> Tuple[Union[str, bytes], Union[str, bytes]]:
    """Call to a manage.py command using call_command."""
    if stdout is None:
        stdout = StringIO()
    if stderr is None:
        stderr = StringIO()
    stdin = kwargs.pop("stdin", StringIO())

    if isinstance(stdin, StringIO):
        with mock.patch("sys.stdin", stdin):
            call_command(*args, stdout=stdout, stderr=stderr, **kwargs)
    else:
        # mock https://docs.python.org/3/library/io.html#io.BufferedReader.read
        def _read_mock(size=None):  # type: ignore # pylint: disable=unused-argument
            return stdin

        with mock.patch("sys.stdin.buffer.read", side_effect=_read_mock):
            call_command(*args, stdout=stdout, stderr=stderr, **kwargs)

    return stdout.getvalue(), stderr.getvalue()


@typing.overload
def cmd_e2e(
    args: typing.Sequence[str],
    *,
    stdin: Optional[Union[StringIO, bytes]] = None,
    stdout: Optional[StringIO] = None,
    stderr: Optional[StringIO] = None,
) -> Tuple[str, str]: ...


@typing.overload
def cmd_e2e(
    args: typing.Sequence[str],
    *,
    stdin: Optional[Union[StringIO, bytes]] = None,
    stdout: BytesIO,
    stderr: Optional[StringIO] = None,
) -> Tuple[bytes, str]: ...


@typing.overload
def cmd_e2e(
    args: typing.Sequence[str],
    *,
    stdin: Optional[Union[StringIO, bytes]] = None,
    stdout: Optional[StringIO] = None,
    stderr: BytesIO,
) -> Tuple[str, bytes]: ...


@typing.overload
def cmd_e2e(
    args: typing.Sequence[str],
    *,
    stdin: Optional[Union[StringIO, bytes]] = None,
    stdout: BytesIO,
    stderr: BytesIO,
) -> Tuple[bytes, bytes]: ...


def cmd_e2e(
    args: typing.Sequence[str],
    stdin: Optional[Union[StringIO, bytes]] = None,
    stdout: Optional[Union[BytesIO, StringIO]] = None,
    stderr: Optional[Union[BytesIO, StringIO]] = None,
) -> Tuple[Union[str, bytes], Union[str, bytes]]:
    """Call a management command the way manage.py does.

    Unlike call_command, this method also tests the argparse configuration of the called command.
    """
    stdout = stdout or StringIO()
    stderr = stderr or StringIO()
    if stdin is None:
        stdin = StringIO()

    if isinstance(stdin, StringIO):
        stdin_mock = mock.patch("sys.stdin", stdin)
    else:

        def _read_mock(size=None):  # type: ignore # pylint: disable=unused-argument
            return stdin

        # TYPE NOTE: mypy detects a different type, but important thing is it's a context manager
        stdin_mock = mock.patch(  # type: ignore[assignment]
            "sys.stdin.buffer.read", side_effect=_read_mock
        )

    # BinaryCommand commands (such as dump_crl) write to sys.stdout.buffer, but BytesIO does not have a
    # buffer attribute, so we manually add the attribute.
    if isinstance(stdout, BytesIO):
        stdout.buffer = stdout  # type: ignore[attr-defined]
    if isinstance(stderr, BytesIO):
        stderr.buffer = stderr  # type: ignore[attr-defined]

    with stdin_mock, mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
        util = ManagementUtility(["manage.py", *args])
        util.execute()

    return stdout.getvalue(), stderr.getvalue()


def crl_distribution_points(
    *distribution_points: x509.DistributionPoint, critical: bool = False
) -> x509.Extension[x509.CRLDistributionPoints]:
    """Shortcut for getting a CRLDistributionPoint extension."""
    value = x509.CRLDistributionPoints(distribution_points)
    return x509.Extension(oid=ExtensionOID.CRL_DISTRIBUTION_POINTS, critical=critical, value=value)


def distribution_point(
    full_name: Optional[Iterable[x509.GeneralName]] = None,
    relative_name: Optional[x509.RelativeDistinguishedName] = None,
    reasons: Optional[typing.FrozenSet[x509.ReasonFlags]] = None,
    crl_issuer: Optional[Iterable[x509.GeneralName]] = None,
) -> x509.DistributionPoint:
    """Shortcut for generating a single distribution point."""
    return x509.DistributionPoint(
        full_name=full_name, relative_name=relative_name, reasons=reasons, crl_issuer=crl_issuer
    )


def extended_key_usage(
    *usages: x509.ObjectIdentifier, critical: bool = False
) -> x509.Extension[x509.ExtendedKeyUsage]:
    """Shortcut for getting an ExtendedKeyUsage extension."""
    return x509.Extension(
        oid=ExtensionOID.EXTENDED_KEY_USAGE, critical=critical, value=x509.ExtendedKeyUsage(usages)
    )


def freshest_crl(
    *distribution_points: x509.DistributionPoint, critical: bool = False
) -> x509.Extension[x509.FreshestCRL]:
    """Shortcut for getting a CRLDistributionPoints extension."""
    return x509.Extension(
        oid=ExtensionOID.FRESHEST_CRL, critical=critical, value=x509.FreshestCRL(distribution_points)
    )


def get_idp(
    full_name: Optional[Iterable[x509.GeneralName]] = None,
    indirect_crl: bool = False,
    only_contains_attribute_certs: bool = False,
    only_contains_ca_certs: bool = False,
    only_contains_user_certs: bool = False,
    only_some_reasons: Optional[typing.FrozenSet[x509.ReasonFlags]] = None,
    relative_name: Optional[x509.RelativeDistinguishedName] = None,
) -> "x509.Extension[x509.IssuingDistributionPoint]":
    """Get an IssuingDistributionPoint extension."""
    return x509.Extension(
        oid=x509.oid.ExtensionOID.ISSUING_DISTRIBUTION_POINT,
        value=x509.IssuingDistributionPoint(
            full_name=full_name,
            indirect_crl=indirect_crl,
            only_contains_attribute_certs=only_contains_attribute_certs,
            only_contains_ca_certs=only_contains_ca_certs,
            only_contains_user_certs=only_contains_user_certs,
            only_some_reasons=only_some_reasons,
            relative_name=relative_name,
        ),
        critical=True,
    )


def idp_full_name(ca: CertificateAuthority) -> Optional[List[x509.UniformResourceIdentifier]]:
    """Get the IDP full name for `ca`."""
    if ca.sign_crl_distribution_points is None:  # pragma: no cover
        return None
    full_names = []
    for dpoint in ca.sign_crl_distribution_points.value:
        if dpoint.full_name:  # pragma: no branch
            full_names += dpoint.full_name
    if full_names:  # pragma: no branch
        return full_names
    return None  # pragma: no cover


def iso_format(value: datetime, timespec: str = "seconds") -> str:
    """Convert a timestamp to ISO, with 'Z' instead of '+00:00'."""
    return value.isoformat(timespec=timespec).replace("+00:00", "Z")


def issuer_alternative_name(
    *names: x509.GeneralName, critical: bool = False
) -> x509.Extension[x509.IssuerAlternativeName]:
    """Shortcut for getting a IssuerAlternativeName extension."""
    return x509.Extension(
        oid=ExtensionOID.ISSUER_ALTERNATIVE_NAME,
        critical=critical,
        value=x509.IssuerAlternativeName(names),
    )


def key_usage(**usages: bool) -> x509.Extension[x509.KeyUsage]:
    """Shortcut for getting a KeyUsage extension."""
    critical = usages.pop("critical", True)
    usages.setdefault("content_commitment", False)
    usages.setdefault("crl_sign", False)
    usages.setdefault("data_encipherment", False)
    usages.setdefault("decipher_only", False)
    usages.setdefault("digital_signature", False)
    usages.setdefault("encipher_only", False)
    usages.setdefault("key_agreement", False)
    usages.setdefault("key_cert_sign", False)
    usages.setdefault("key_encipherment", False)
    return x509.Extension(oid=ExtensionOID.KEY_USAGE, critical=critical, value=x509.KeyUsage(**usages))


def name_constraints(
    permitted: Optional[Iterable[x509.GeneralName]] = None,
    excluded: Optional[Iterable[x509.GeneralName]] = None,
    critical: bool = True,
) -> x509.Extension[x509.NameConstraints]:
    """Shortcut for getting a NameConstraints extension."""
    return x509.Extension(
        oid=ExtensionOID.NAME_CONSTRAINTS,
        value=x509.NameConstraints(permitted_subtrees=permitted, excluded_subtrees=excluded),
        critical=critical,
    )


def ocsp_no_check(critical: bool = False) -> x509.Extension[x509.OCSPNoCheck]:
    """Shortcut for getting a OCSPNoCheck extension."""
    return x509.Extension(oid=ExtensionOID.OCSP_NO_CHECK, critical=critical, value=x509.OCSPNoCheck())


def precert_poison() -> x509.Extension[x509.PrecertPoison]:
    """Shortcut for getting a PrecertPoison extension."""
    return x509.Extension(oid=ExtensionOID.PRECERT_POISON, critical=True, value=x509.PrecertPoison())


def subject_alternative_name(
    *names: x509.GeneralName, critical: bool = False
) -> x509.Extension[x509.SubjectAlternativeName]:
    """Shortcut for getting a SubjectAlternativeName extension."""
    return x509.Extension(
        oid=ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
        critical=critical,
        value=x509.SubjectAlternativeName(names),
    )


def subject_key_identifier(
    cert: Union[X509CertMixin, x509.Certificate],
) -> x509.Extension[x509.SubjectKeyIdentifier]:
    """Shortcut for getting a SubjectKeyIdentifier extension."""
    if isinstance(cert, X509CertMixin):
        cert = cert.pub.loaded

    ski = x509.SubjectKeyIdentifier.from_public_key(cert.public_key())
    return x509.Extension(oid=ExtensionOID.SUBJECT_KEY_IDENTIFIER, critical=False, value=ski)


def tls_feature(*features: x509.TLSFeatureType, critical: bool = False) -> x509.Extension[x509.TLSFeature]:
    """Shortcut for getting a TLSFeature extension."""
    return x509.Extension(oid=ExtensionOID.TLS_FEATURE, critical=critical, value=x509.TLSFeature(features))


FuncTypeVar = typing.TypeVar("FuncTypeVar", bound=typing.Callable[..., Any])


def dns(name: str) -> x509.DNSName:  # just a shortcut
    """Shortcut to get a :py:class:`cg:cryptography.x509.DNSName`."""
    return x509.DNSName(name)


def uri(url: str) -> x509.UniformResourceIdentifier:  # just a shortcut
    """Shortcut to get a :py:class:`cg:cryptography.x509.UniformResourceIdentifier`."""
    return x509.UniformResourceIdentifier(url)


def ip(
    name: Union[ipaddress.IPv4Address, ipaddress.IPv6Address, ipaddress.IPv4Network, ipaddress.IPv6Network],
) -> x509.IPAddress:
    """Shortcut to get a :py:class:`cg:cryptography.x509.IPAddress`."""
    return x509.IPAddress(name)


def rdn(
    name: Iterable[Tuple[x509.ObjectIdentifier, str]],
) -> x509.RelativeDistinguishedName:  # just a shortcut
    """Shortcut to get a :py:class:`cg:cryptography.x509.RelativeDistinguishedName`."""
    return x509.RelativeDistinguishedName([x509.NameAttribute(*t) for t in name])


@contextmanager
def mock_slug() -> Iterator[str]:
    """Mock random slug generation, yields the static value."""
    slug = get_random_string(length=12)
    with mock.patch("django_ca.models.get_random_string", return_value=slug):
        yield slug


STRIP_WHITESPACE = doctest.register_optionflag("STRIP_WHITESPACE")


class OutputChecker(doctest.OutputChecker):
    """Custom output checker to enable the STRIP_WHITESPACE option."""

    def check_output(self, want: str, got: str, optionflags: int) -> bool:
        if optionflags & STRIP_WHITESPACE:
            want = re.sub(r"\s*", "", want)
            got = re.sub(r"\s*", "", got)
        return super().check_output(want, got, optionflags)


def doctest_module(
    module: str,
    name: Optional[str] = None,
    globs: Optional[Dict[str, str]] = None,
    verbose: Optional[bool] = False,
    report: bool = False,
    optionflags: int = 0,
    extraglobs: Optional[Dict[str, str]] = None,
    raise_on_error: bool = False,
    exclude_empty: bool = False,
) -> doctest.TestResults:
    """Shortcut for running doctests in the given Python module.

    This function uses a custom OutputChecker to enable the ``STRIP_WHITESPACE`` doctest option. This option
    will remove all whitespace (including newlines) from the both actual and expected output. It is used for
    formatting actual output with newlines to improve readability.

    This function is otherwise based on ``doctest.testmod``. It differs in that it will interpret `module`
    as module path if a ``str`` and import the module. The `report` and `verbose` flags also default to
    ``False``, as this provides cleaner output in modules with a lot of doctests.
    """
    finder = doctest.DocTestFinder(exclude_empty=exclude_empty)
    checker = OutputChecker()

    if raise_on_error:  # pragma: no cover  # only used for debugging
        runner: doctest.DocTestRunner = doctest.DebugRunner(
            verbose=verbose, optionflags=optionflags, checker=checker
        )
    else:
        runner = doctest.DocTestRunner(verbose=verbose, optionflags=optionflags, checker=checker)

    mod = importlib.import_module(module)

    for test in finder.find(mod, name, globs=globs, extraglobs=extraglobs):
        runner.run(test)

    if report:  # pragma: no cover  # only used for debugging
        runner.summarize()

    return doctest.TestResults(runner.failures, runner.tries)


class override_tmpcadir(override_settings):  # pylint: disable=invalid-name; in line with parent class
    """Sets the CA_DIR directory to a temporary directory.

    .. NOTE: This also takes any additional settings.
    """

    def __call__(self, test_func: FuncTypeVar) -> FuncTypeVar:
        if not inspect.isfunction(test_func):
            raise ValueError("Only functions can use override_tmpcadir()")
        return super().__call__(test_func)  # type: ignore[return-value]  # cannot figure out what's here

    def enable(self) -> None:
        tmpdir = tempfile.mkdtemp()
        self.options["CA_DIR"] = tmpdir
        self.options["STORAGES"] = settings.STORAGES
        self.options["STORAGES"]["django-ca"]["OPTIONS"]["location"] = tmpdir

        # copy CAs
        for filename in [v["key_filename"] for v in CERT_DATA.values() if v["key_filename"] is not False]:
            shutil.copy(os.path.join(FIXTURES_DIR, filename), tmpdir)

        # Copy OCSP public key (required for OCSP tests)
        shutil.copy(os.path.join(FIXTURES_DIR, CERT_DATA["profile-ocsp"]["pub_filename"]), tmpdir)

        # Reset profiles, so that they are loaded again on first access
        profiles._reset()  # pylint: disable=protected-access

        super().enable()

    def disable(self) -> None:
        super().disable()
        shutil.rmtree(self.options["CA_DIR"])
