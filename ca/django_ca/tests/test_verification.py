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

"""Validate certificates using the openssl command line tool."""

import os
import re
import shlex
import subprocess
import tempfile
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone as tz
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtensionOID, NameOID

from django.urls import reverse

import pytest
from pytest_django.fixtures import SettingsWrapper

from django_ca.key_backends import key_backends
from django_ca.key_backends.storages.models import StoragesCreatePrivateKeyOptions
from django_ca.models import CertificateAuthority, X509CertMixin
from django_ca.tests.base.constants import CERT_DATA
from django_ca.tests.base.utils import (
    cmd,
    crl_distribution_points,
    distribution_point,
    override_tmpcadir,
    uri,
)

pytestmark = [pytest.mark.usefixtures("tmpcadir"), pytest.mark.django_db]


def assert_full_name(
    parsed_crl: x509.CertificateRevocationList, expected: Optional[list[x509.GeneralName]] = None
) -> None:
    """Assert that the full name of the Issuing Distribution Point of the CRL matches `expected`."""
    idp = parsed_crl.extensions.get_extension_for_class(x509.IssuingDistributionPoint).value
    assert idp.full_name == expected


def assert_no_issuing_distribution_point(parsed_crl: x509.CertificateRevocationList) -> None:
    """Assert that the given CRL has *no* IssuingDistributionPoint extension."""
    try:
        idp = parsed_crl.extensions.get_extension_for_class(x509.IssuingDistributionPoint)
        pytest.fail(f"CRL contains an IssuingDistributionPoint extension: {idp}")
    except x509.ExtensionNotFound:
        pass


def assert_scope(
    parsed_crl: x509.CertificateRevocationList, ca: bool = False, user: bool = False, attribute: bool = False
) -> None:
    """Assert that the scope in the Issuing Distribution Point matches what we expect."""
    idp = parsed_crl.extensions.get_extension_for_class(x509.IssuingDistributionPoint).value
    assert idp.only_contains_ca_certs is ca, idp
    assert idp.only_contains_user_certs is user, idp
    assert idp.only_contains_attribute_certs is attribute, idp


def init_ca(name: str, **kwargs: Any) -> CertificateAuthority:
    """Create a CA."""
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    kwargs.setdefault("not_after", datetime.now(tz=tz.utc) + timedelta(days=365 * 2))
    key_backend = key_backends["default"]
    key_backend_options = StoragesCreatePrivateKeyOptions(
        key_type="RSA", password=None, path="ca", key_size=1024
    )
    if kwargs.get("parent"):
        kwargs["use_parent_private_key_options"] = key_backend.use_model(password=None)
    return CertificateAuthority.objects.init(name, key_backend, key_backend_options, subject, **kwargs)


@contextmanager
def crl(ca: CertificateAuthority, **kwargs: Any) -> Iterator[tuple[str, x509.CertificateRevocationList]]:
    """Dump CRL to a tmpdir, yield path to it."""
    kwargs["ca"] = ca
    with tempfile.TemporaryDirectory() as tempdir:
        path = os.path.join(tempdir, f"{ca.name}.{kwargs.get('scope')}.crl")
        cmd("dump_crl", path, **kwargs)

        with open(path, "rb") as stream:
            loaded_crl = x509.load_pem_x509_crl(stream.read())

        yield path, loaded_crl


@contextmanager
def dumped(*certificates: X509CertMixin) -> Iterator[list[str]]:
    """Dump certificates to a tempdir, yield list of paths."""
    with tempfile.TemporaryDirectory() as tempdir:
        paths = []
        for cert in certificates:
            path = os.path.join(tempdir, f"{cert.serial}.pem")
            paths.append(path)
            with open(path, "w", encoding="ascii") as stream:
                stream.write(cert.pub.pem)

        yield paths


@contextmanager
def sign_cert(ca: CertificateAuthority, hostname: str = "example.com", **kwargs: Any) -> Iterator[str]:
    """Create a signed certificate in a temporary directory."""
    stdin = CERT_DATA["root-cert"]["csr"]["parsed"].public_bytes(Encoding.PEM)
    subject = f"CN={hostname}"

    with tempfile.TemporaryDirectory() as tempdir:
        out_path = os.path.join(tempdir, f"{hostname}.pem")
        cmd("sign_cert", ca=ca, subject=subject, out=out_path, stdin=stdin, **kwargs)
        yield out_path


def openssl(command: str, *args: str, code: int = 0, **kwargs: str) -> None:
    """Run openssl."""
    exp_stdout = kwargs.pop("stdout", False)
    exp_stderr = kwargs.pop("stderr", False)
    command = command.format(*args, **kwargs)
    if kwargs.pop("verbose", False):
        print(f"openssl {command}")
    proc = subprocess.run(["openssl", *shlex.split(command)], capture_output=True, check=False)
    stdout = proc.stdout.decode("utf-8")
    stderr = proc.stderr.decode("utf-8")
    assert proc.returncode == code, stderr
    if isinstance(exp_stdout, str):
        assert re.search(exp_stdout, stdout) is not None, stdout
    if isinstance(exp_stderr, str):
        assert re.search(exp_stderr, stderr) is not None, stderr


def verify(
    command: str,
    *args: str,
    untrusted: Optional[Iterable[str]] = None,
    crl_path: Optional[Iterable[str]] = None,
    code: int = 0,
    **kwargs: str,
) -> None:
    """Run openssl verify."""
    if untrusted:
        untrusted_args = " ".join(f"-untrusted {path}" for path in untrusted)
        command = f"{untrusted_args} {command}"
    if crl_path:
        crlfile_args = " ".join(f"-CRLfile {path}" for path in crl_path)
        command = f"{crlfile_args} {command}"

    openssl(f"verify {command}", *args, code=code, **kwargs)


def test_root_ca(ca_name: str) -> None:
    """Try validating a root CA."""
    ca = init_ca(ca_name)

    # Very simple validation of the Root CRL
    with dumped(ca) as paths:
        verify("-CAfile {0} {0}", *paths)

    # Create a CRL too and include it
    with dumped(ca) as paths, crl(ca, only_contains_ca_certs=True) as (crl_path, crl_parsed):
        verify("-CAfile {0} -crl_check_all {0}", *paths, crl_path=[crl_path])

    # Try again with no scope
    with dumped(ca) as paths, crl(ca) as (crl_path, crl_parsed):
        verify("-CAfile {0} -crl_check_all {0}", *paths, crl_path=[crl_path])

    # Try with cert scope (fails because of wrong scope
    with (
        dumped(ca) as paths,
        crl(ca, only_contains_user_certs=True) as (crl_path, crl_parsed),
        pytest.raises(AssertionError),
    ):
        verify("-CAfile {0} -crl_check_all {0}", *paths, crl_path=[crl_path])


def test_root_ca_cert(ca_name: str) -> None:
    """Try validating a cert issued by the root CA."""
    ca = init_ca(ca_name)

    with dumped(ca) as paths, sign_cert(ca) as cert:
        verify("-CAfile {0} {cert}", *paths, cert=cert)

        # Create a CRL too and include it
        with crl(ca, only_contains_user_certs=True) as (crl_path, crl_parsed):
            assert_scope(crl_parsed, user=True)
            verify("-CAfile {0} -crl_check {cert}", *paths, crl_path=[crl_path], cert=cert)

            # for crl_check_all, we also need the root CRL
            with crl(ca, only_contains_ca_certs=True) as (crl2_path, crl2):
                assert_scope(crl2, ca=True)
                verify("-CAfile {0} -crl_check_all {cert}", *paths, crl_path=[crl_path, crl2_path], cert=cert)

        # Try a single CRL with a global scope
        with crl(ca, scope=None) as (crl_global_path, crl_global):
            assert_no_issuing_distribution_point(crl_global)
            verify("-CAfile {0} -crl_check_all {cert}", *paths, crl_path=[crl_global_path], cert=cert)


def test_ca_default_hostname(ca_name: str) -> None:
    """Test that CA_DEFAULT_HOSTNAME does not lead to problems."""
    ca = init_ca(ca_name)
    # Root CAs have no CRLDistributionPoints
    assert ExtensionOID.CRL_DISTRIBUTION_POINTS not in ca.extensions

    with dumped(ca) as paths, sign_cert(ca) as cert:
        with crl(ca) as (crl_path, crl_parsed):  # test global CRL
            assert_no_issuing_distribution_point(crl_parsed)
            verify("-trusted {0} -crl_check {cert}", *paths, crl_path=[crl_path], cert=cert)
            verify("-trusted {0} -crl_check_all {cert}", *paths, crl_path=[crl_path], cert=cert)

        with crl(ca, only_contains_user_certs=True) as (crl_path, crl_parsed):  # test user-only CRL
            assert_scope(crl_parsed, user=True)
            verify("-trusted {0} -crl_check {cert}", *paths, crl_path=[crl_path], cert=cert)
            # crl_check_all does not work,  b/c the scope  is only "user"
            verify(
                "-trusted {0} -crl_check_all {cert}",
                *paths,
                crl_path=[crl_path],
                cert=cert,
                code=2,
                stderr="[dD]ifferent CRL scope",
            )


@override_tmpcadir(CA_DEFAULT_HOSTNAME="")
def test_intermediate_ca(ca_name: str) -> None:
    """Validate intermediate CA and its certs."""
    root = init_ca(f"{ca_name}_root", path_length=2)
    child = init_ca(f"{ca_name}_child", parent=root, path_length=1)
    grandchild = init_ca(f"{ca_name}_grandchild", parent=child)

    #  Verify the state of the CAs themselves.
    assert ExtensionOID.CRL_DISTRIBUTION_POINTS not in root.extensions
    assert ExtensionOID.CRL_DISTRIBUTION_POINTS not in child.extensions
    assert ExtensionOID.CRL_DISTRIBUTION_POINTS not in grandchild.extensions

    with dumped(root, child, grandchild) as paths:
        untrusted = paths[1:]
        # Simple validation of the CAs
        verify("-CAfile {0} {1}", *paths)
        verify("-CAfile {0} -untrusted {1} {2}", *paths)

        # Try validation with CRLs
        with (
            crl(root, only_contains_ca_certs=True) as (crl1_path, crl1),
            crl(child, only_contains_ca_certs=True) as (crl2_path, crl2),
        ):
            verify("-CAfile {0} -untrusted {1} -crl_check_all {2}", *paths, crl_path=[crl1_path, crl2_path])

            with sign_cert(child) as cert, crl(child, only_contains_user_certs=True) as (crl3_path, crl3):
                verify("-CAfile {0} -untrusted {1} {cert}", *paths, cert=cert)
                verify(
                    "-CAfile {0} -untrusted {1} {cert}", *paths, cert=cert, crl_path=[crl1_path, crl3_path]
                )

            with (
                sign_cert(grandchild) as cert,
                crl(child, only_contains_ca_certs=True) as (crl4_path, crl4),
                crl(grandchild, only_contains_user_certs=True) as (crl6_path, crl6),
            ):
                verify("-CAfile {0} {cert}", *paths, untrusted=untrusted, cert=cert)
                verify(
                    "-CAfile {0} -crl_check_all {cert}",
                    *paths,
                    untrusted=untrusted,
                    crl_path=[crl1_path, crl4_path, crl6_path],
                    cert=cert,
                )


@override_tmpcadir(CA_DEFAULT_HOSTNAME="example.com")
def test_intermediate_ca_default_hostname(ca_name: str, settings: SettingsWrapper) -> None:
    """Test that a changing CA_DEFAULT_HOSTNAME does not lead to problems."""
    root = init_ca(f"{ca_name}_root", path_length=2)
    child = init_ca(f"{ca_name}_child", parent=root, path_length=1)
    grandchild = init_ca(f"{ca_name}_grandchild", parent=child)

    child_ca_crl = reverse("django_ca:ca-crl", kwargs={"serial": root.serial})
    grandchild_ca_crl = reverse("django_ca:ca-crl", kwargs={"serial": child.serial})

    #  Verify the state of the CAs themselves.
    assert ExtensionOID.CRL_DISTRIBUTION_POINTS not in root.extensions
    assert child.extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS] == crl_distribution_points(
        distribution_point([uri(f"http://example.com{child_ca_crl}")])
    )

    assert grandchild.extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS] == crl_distribution_points(
        distribution_point([uri(f"http://example.com{grandchild_ca_crl}")]),
    )

    with (
        dumped(root, child, grandchild) as paths,
        crl(root, only_contains_ca_certs=True) as (root_ca_crl_path, root_ca_crl_parsed),
    ):
        # Simple validation of the CAs
        verify("-trusted {0} {1}", *paths)
        verify("-trusted {0} -untrusted {1} {2}", *paths)

        with crl(child, only_contains_ca_certs=True) as (child_ca_crl_path, child_ca_crl_parsed):
            assert_full_name(child_ca_crl_parsed, None)
            verify(
                "-trusted {0} -untrusted {1} -crl_check_all {2}",
                *paths,
                crl_path=[root_ca_crl_path, child_ca_crl_path],
            )

        # Globally scoped CRLs validates as well (no full name)
        with crl(child) as (child_crl_path, child_crl_parsed):
            verify(
                "-trusted {0} -untrusted {1} -crl_check_all {2}",
                *paths,
                crl_path=[root_ca_crl_path, child_crl_path],
                code=0,
            )

        # Again, global CRL validates
        settings.CA_DEFAULT_HOSTNAME = "example.net"
        with (
            crl(root, only_contains_ca_certs=True) as (crl_path, crl_parsed),
            crl(child) as (crl2_path, crl_parsed_2),
        ):
            assert_full_name(crl_parsed, None)
            verify(
                "-trusted {0} -untrusted {1} -crl_check_all {2}",
                *paths,
                crl_path=[crl_path, crl2_path],
                code=0,
            )
