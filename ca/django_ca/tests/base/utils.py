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

import inspect
import ipaddress
import os
import shutil
import tempfile
import textwrap
import typing
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from datetime import datetime
from io import BytesIO, StringIO
from typing import Any, Optional, Union
from unittest import mock

from pydantic import BaseModel

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificateIssuerPublicKeyTypes,
)
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID

from django.conf import settings
from django.core.files.storage import storages
from django.core.management import ManagementUtility, call_command
from django.test import override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string

from django_ca.extensions import extension_as_text
from django_ca.key_backends import KeyBackend
from django_ca.models import CertificateAuthority, X509CertMixin
from django_ca.profiles import profiles
from django_ca.tests.acme.views.constants import SERVER_NAME
from django_ca.tests.base.constants import CERT_DATA, FIXTURES_DIR
from django_ca.typehints import AllowedHashTypes, ArgumentGroup, CertificateExtension, ParsableKeyType


class DummyModel(BaseModel):
    """Dummy model for the dummy backend."""


class DummyBackend(KeyBackend[DummyModel, DummyModel, DummyModel]):  # pragma: no cover
    """Backend with no actions whatsoever."""

    title = "dummy backend"
    description = "dummy description"

    # This backend only supports RSA and EC keys, but also the (invented) "STRANGE" key type.
    supported_key_types = ("RSA", "EC", "STRANGE")
    supported_elliptic_curves = ("sect571r1",)
    supported_hash_algorithms = ("SHA-256", "SHA-512")

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, DummyBackend)

    def add_create_private_key_arguments(self, group: ArgumentGroup) -> None:
        return None

    def add_store_private_key_arguments(self, group: ArgumentGroup) -> None:
        return None

    def get_create_private_key_options(
        self,
        key_type: ParsableKeyType,
        key_size: Optional[int],
        elliptic_curve: Optional[str],
        options: dict[str, Any],
    ) -> DummyModel:
        return DummyModel()

    def add_use_parent_private_key_arguments(self, group: ArgumentGroup) -> None:
        return None

    def get_use_parent_private_key_options(
        self, ca: CertificateAuthority, options: dict[str, Any]
    ) -> DummyModel:
        return DummyModel()

    def get_store_private_key_options(self, options: dict[str, Any]) -> DummyModel:
        return DummyModel()

    def create_private_key(
        self, ca: CertificateAuthority, key_type: ParsableKeyType, options: DummyModel
    ) -> tuple[CertificateIssuerPublicKeyTypes, DummyModel]:
        return None, DummyModel()  # type: ignore[return-value]

    def get_use_private_key_options(self, ca: CertificateAuthority, options: dict[str, Any]) -> DummyModel:
        return DummyModel()

    def is_usable(
        self, ca: "CertificateAuthority", use_private_key_options: Optional[DummyModel] = None
    ) -> bool:
        return True

    def check_usable(self, ca: "CertificateAuthority", use_private_key_options: DummyModel) -> None:
        return

    def sign_certificate_revocation_list(
        self,
        ca: "CertificateAuthority",
        use_private_key_options: DummyModel,
        builder: x509.CertificateRevocationListBuilder,
        algorithm: Optional[AllowedHashTypes],
    ) -> x509.CertificateRevocationList:
        return None  # type: ignore[return-value]

    def sign_certificate(
        self,
        ca: "CertificateAuthority",
        use_private_key_options: DummyModel,
        public_key: CertificateIssuerPublicKeyTypes,
        serial: int,
        algorithm: Optional[AllowedHashTypes],
        issuer: x509.Name,
        subject: x509.Name,
        expires: datetime,
        extensions: Sequence[CertificateExtension],
    ) -> x509.Certificate:
        return None  # type: ignore[return-value]

    def store_private_key(
        self,
        ca: "CertificateAuthority",
        key: CertificateIssuerPrivateKeyTypes,
        certificate: x509.Certificate,
        options: DummyModel,
    ) -> None:
        return None


def root_reverse(name: str, **kwargs: Any) -> str:
    """Shortcut to get a django-ca url with a root serial."""
    kwargs.setdefault("serial", CERT_DATA["root"]["serial"])
    return reverse(f"django_ca:{name}", kwargs=kwargs)


def root_uri(name: str, hostname: Optional[str] = None, **kwargs: Any) -> str:
    """Full URI with a root serial."""
    if not hostname:  # pragma: no branch
        hostname = SERVER_NAME
    path = root_reverse(name, **kwargs)
    return f"http://{hostname}{path}"


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
def cmd(*args: Any, stdout: BytesIO, stderr: BytesIO, **kwargs: Any) -> tuple[bytes, bytes]: ...


@typing.overload
def cmd(
    *args: Any, stdout: BytesIO, stderr: Optional[StringIO] = None, **kwargs: Any
) -> tuple[bytes, str]: ...


@typing.overload
def cmd(
    *args: Any, stdout: Optional[StringIO] = None, stderr: BytesIO, **kwargs: Any
) -> tuple[str, bytes]: ...


@typing.overload
def cmd(
    *args: Any, stdout: Optional[StringIO] = None, stderr: Optional[StringIO] = None, **kwargs: Any
) -> tuple[str, str]: ...


def cmd(
    *args: Any,
    stdout: Optional[Union[StringIO, BytesIO]] = None,
    stderr: Optional[Union[StringIO, BytesIO]] = None,
    **kwargs: Any,
) -> tuple[Union[str, bytes], Union[str, bytes]]:
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
) -> tuple[str, str]: ...


@typing.overload
def cmd_e2e(
    args: typing.Sequence[str],
    *,
    stdin: Optional[Union[StringIO, bytes]] = None,
    stdout: BytesIO,
    stderr: Optional[StringIO] = None,
) -> tuple[bytes, str]: ...


@typing.overload
def cmd_e2e(
    args: typing.Sequence[str],
    *,
    stdin: Optional[Union[StringIO, bytes]] = None,
    stdout: Optional[StringIO] = None,
    stderr: BytesIO,
) -> tuple[str, bytes]: ...


@typing.overload
def cmd_e2e(
    args: typing.Sequence[str],
    *,
    stdin: Optional[Union[StringIO, bytes]] = None,
    stdout: BytesIO,
    stderr: BytesIO,
) -> tuple[bytes, bytes]: ...


def cmd_e2e(
    args: typing.Sequence[str],
    stdin: Optional[Union[StringIO, bytes]] = None,
    stdout: Optional[Union[BytesIO, StringIO]] = None,
    stderr: Optional[Union[BytesIO, StringIO]] = None,
) -> tuple[Union[str, bytes], Union[str, bytes]]:
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


def cn(value: str) -> x509.NameAttribute:
    """Shortcut for creating a common name attr."""
    return x509.NameAttribute(NameOID.COMMON_NAME, value)


def country(value: str) -> x509.NameAttribute:
    """Shortcut for creating a country attr."""
    return x509.NameAttribute(NameOID.COUNTRY_NAME, value)


def crl_distribution_points(
    *distribution_points: x509.DistributionPoint, critical: bool = False
) -> x509.Extension[x509.CRLDistributionPoints]:
    """Shortcut for getting a CRLDistributionPoint extension."""
    value = x509.CRLDistributionPoints(distribution_points)
    return x509.Extension(oid=ExtensionOID.CRL_DISTRIBUTION_POINTS, critical=critical, value=value)


def distribution_point(
    full_name: Optional[Iterable[x509.GeneralName]] = None,
    relative_name: Optional[x509.RelativeDistinguishedName] = None,
    reasons: Optional[frozenset[x509.ReasonFlags]] = None,
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


def get_cert_context(name: str) -> dict[str, Any]:
    """Get a dictionary suitable for testing output based on the dictionary in basic.certs."""
    ctx: dict[str, Any] = {}

    for key, value in sorted(CERT_DATA[name].items()):
        # Handle cryptography extensions
        if key == "extensions":
            ctx["extensions"] = {ext["type"]: ext for ext in CERT_DATA[name].get("extensions", [])}
        elif key == "precert_poison":
            ctx["precert_poison"] = "* Precert Poison (critical):\n  Yes"
        elif isinstance(value, x509.Extension):
            if value.critical:
                ctx[f"{key}_critical"] = " (critical)"
            else:
                ctx[f"{key}_critical"] = ""

            ctx[f"{key}_text"] = textwrap.indent(extension_as_text(value.value), "  ")
        elif key == "path_length":
            ctx[key] = value
            ctx[f"{key}_text"] = "unlimited" if value is None else value
        else:
            ctx[key] = value

    if parent := CERT_DATA[name].get("parent"):
        ctx["parent_name"] = CERT_DATA[parent]["name"]
        ctx["parent_serial"] = CERT_DATA[parent]["serial"]
        ctx["parent_serial_colons"] = CERT_DATA[parent]["serial_colons"]

    if CERT_DATA[name]["key_filename"] is not False:
        storage = storages["django-ca"]
        ctx["key_path"] = storage.path(CERT_DATA[name]["key_filename"])
    return ctx


def get_idp(
    full_name: Optional[Iterable[x509.GeneralName]] = None,
    indirect_crl: bool = False,
    only_contains_attribute_certs: bool = False,
    only_contains_ca_certs: bool = False,
    only_contains_user_certs: bool = False,
    only_some_reasons: Optional[frozenset[x509.ReasonFlags]] = None,
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


def idp_full_name(ca: CertificateAuthority) -> Optional[list[x509.UniformResourceIdentifier]]:
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
    if isinstance(cert, X509CertMixin):  # pragma: no branch - usually full certificate is passed.
        cert = cert.pub.loaded

    ski = x509.SubjectKeyIdentifier.from_public_key(cert.public_key())
    return x509.Extension(oid=ExtensionOID.SUBJECT_KEY_IDENTIFIER, critical=False, value=ski)


def state(value: str) -> x509.NameAttribute:
    """Return a state name attr."""
    return x509.NameAttribute(oid=NameOID.STATE_OR_PROVINCE_NAME, value=value)


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
    name: Iterable[tuple[x509.ObjectIdentifier, str]],
) -> x509.RelativeDistinguishedName:  # just a shortcut
    """Shortcut to get a :py:class:`cg:cryptography.x509.RelativeDistinguishedName`."""
    return x509.RelativeDistinguishedName([x509.NameAttribute(*t) for t in name])


@contextmanager
def mock_slug() -> Iterator[str]:
    """Mock random slug generation, yields the static value."""
    slug = get_random_string(length=12)
    with mock.patch("django_ca.models.get_random_string", return_value=slug):
        yield slug


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
