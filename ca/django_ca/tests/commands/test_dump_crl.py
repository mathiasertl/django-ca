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

"""Test the dump_crl management command."""

import os
import re
from datetime import timedelta
from io import BytesIO
from pathlib import Path
from typing import Any
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import CRLEntryExtensionOID, NameOID

from django.utils import timezone

import pytest
from pytest_django.fixtures import SettingsWrapper

from django_ca.models import Certificate, CertificateAuthority
from django_ca.tests.base.assertions import (
    assert_command_error,
    assert_crl,
    assert_e2e_command_error,
    assert_revoked,
)
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS
from django_ca.tests.base.utils import (
    cmd,
    crl_distribution_points,
    distribution_point,
    get_idp,
    idp_full_name,
)

# freeze time as otherwise CRLs might have rounding errors
pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])]


def dump_crl(*args: Any, **kwargs: Any) -> bytes:
    """Execute the dump_crl command."""
    out, err = cmd("dump_crl", *args, stdout=BytesIO(), stderr=BytesIO(), **kwargs)
    assert err == b""
    return out


def test_command(usable_ca: CertificateAuthority) -> None:
    """Test the command for every usable CA."""
    stdout = dump_crl(ca=usable_ca, scope="user")
    expected_idp = get_idp(full_name=idp_full_name(usable_ca), only_contains_user_certs=True)
    assert_crl(stdout, signer=usable_ca, algorithm=usable_ca.algorithm, idp=expected_idp)


def test_rsa_ca_with_sha512(usable_root: CertificateAuthority) -> None:
    """Test creating a CRL from an RSA key with a custom algorithm."""
    hash_cls = hashes.SHA512
    assert not isinstance(usable_root.algorithm, hash_cls)  # make sure that test has a point
    stdout = dump_crl(ca=usable_root, scope="user", algorithm=hash_cls())
    expected_idp = get_idp(full_name=idp_full_name(usable_root), only_contains_user_certs=True)
    assert_crl(stdout, signer=usable_root, algorithm=hash_cls(), idp=expected_idp)


def test_file(tmp_path: Path, usable_root: CertificateAuthority) -> None:
    """Test dumping to a file."""
    path = os.path.join(tmp_path, "crl-test.crl")
    stdout = dump_crl(path, ca=usable_root, scope="user")
    assert stdout == b""

    with open(path, "rb") as stream:
        crl = stream.read()
    expected_idp = get_idp(full_name=idp_full_name(usable_root), only_contains_user_certs=True)
    assert_crl(crl, signer=usable_root, algorithm=usable_root.algorithm, idp=expected_idp)


def test_file_with_destination_does_not_exist(tmp_path: Path, usable_root: CertificateAuthority) -> None:
    """Test dumping to a file where the destination does not exist."""
    path = os.path.join(tmp_path, "test", "crl-test.crl")

    with assert_command_error(rf"^\[Errno 2\] No such file or directory: '{re.escape(path)}'$"):
        dump_crl(path, ca=usable_root, scope="user")


def test_pwd_ca_with_missing_password(settings: SettingsWrapper, usable_pwd: CertificateAuthority) -> None:
    """Test creating a CRL for a CA with a password without giving a password."""
    settings.CA_PASSWORDS = {}
    with assert_command_error(r"^Password was not given but private key is encrypted$"):
        dump_crl(ca=usable_pwd, scope="user")


def test_pwd_ca_with_wrong_password(usable_pwd: CertificateAuthority) -> None:
    """Test creating a CRL for a CA with a password with the wrong password."""
    with assert_command_error(r"^Could not decrypt private key - bad password\?$"):
        dump_crl(ca=usable_pwd, scope="user", password=b"wrong")


def test_pwd_ca(usable_pwd: CertificateAuthority) -> None:
    """Test creating a CRL for a CA with a password with the wrong password."""
    stdout = dump_crl(ca=usable_pwd, scope="user", password=CERT_DATA["pwd"]["password"])

    expected_idp = get_idp(full_name=idp_full_name(usable_pwd), only_contains_user_certs=True)
    assert_crl(stdout, signer=usable_pwd, algorithm=usable_pwd.algorithm, idp=expected_idp)


def test_pwd_ca_with_password_in_settings(
    settings: SettingsWrapper, usable_pwd: CertificateAuthority
) -> None:
    """Test creating a CRL with a CA with a password."""
    settings.CA_PASSWORDS = {usable_pwd.serial: CERT_DATA["pwd"]["password"]}

    # This works because CA_PASSWORDS is set
    stdout = dump_crl(ca=usable_pwd, scope="user")

    expected_idp = get_idp(full_name=idp_full_name(usable_pwd), only_contains_user_certs=True)
    assert_crl(stdout, signer=usable_pwd, algorithm=usable_pwd.algorithm, idp=expected_idp)


def test_no_scope_with_root_ca(usable_root: CertificateAuthority) -> None:
    """Test no-scope CRL for root CA."""
    # For Root CAs, there should not be an IssuingDistributionPoint extension in this case.
    stdout = dump_crl(ca=usable_root, scope=None)
    assert_crl(
        stdout, encoding=Encoding.PEM, expires=86400, signer=usable_root, algorithm=usable_root.algorithm
    )


def test_no_scope_with_child_ca(usable_child: CertificateAuthority) -> None:
    """Test no-scope CRL for child CA."""
    idp = get_idp(full_name=idp_full_name(usable_child))
    stdout = dump_crl(ca=usable_child, scope=None)
    assert_crl(
        stdout,
        encoding=Encoding.PEM,
        expires=86400,
        signer=usable_child,
        idp=idp,
        algorithm=usable_child.algorithm,
    )


def test_include_issuing_distribution_point(usable_root: CertificateAuthority) -> None:
    """Test forcing the inclusion of the IssuingDistributionPoint extension.

    Note: The only case where it is not included is for CRLs for root CAs with no scope, in which case not
    enough information is available to even add the extension, so the test here asserts that the call
    raises an extension.
    """
    assert_e2e_command_error(
        ["dump_crl", f"--ca={usable_root.serial}", "--include-issuing-distribution-point"],
        b"Cannot add IssuingDistributionPoint extension to CRLs with no scope for root CAs.",
        b"",
    )


def test_exclude_issuing_distribution_point_with_root_ca(usable_root: CertificateAuthority) -> None:
    """Test forcing the exclusion of the IssuingDistributionPoint extension."""
    # For Root CAs, there should not be an IssuingDistributionPoint extension, test that forced exclusion
    # does not break this.
    stdout = dump_crl(ca=usable_root, include_issuing_distribution_point=False)
    assert_crl(
        stdout,
        encoding=Encoding.PEM,
        expires=86400,
        signer=usable_root,
        idp=None,
        algorithm=usable_root.algorithm,
    )


def test_exclude_issuing_distribution_point_with_child_ca(usable_child: CertificateAuthority) -> None:
    """Test forcing the exclusion of the IssuingDistributionPoint extension."""
    stdout = dump_crl(ca=usable_child, include_issuing_distribution_point=False)
    assert_crl(
        stdout,
        encoding=Encoding.PEM,
        expires=86400,
        signer=usable_child,
        idp=None,
        algorithm=usable_child.algorithm,
    )


def test_no_full_name_in_sign_crl_distribution_point(usable_child: CertificateAuthority) -> None:
    """Test dumping a CRL where the CRL Distribution Point extension for signing has only an RDN."""
    usable_child.sign_crl_distribution_points = crl_distribution_points(
        distribution_point(
            relative_name=x509.RelativeDistinguishedName(
                [x509.NameAttribute(oid=NameOID.COMMON_NAME, value="example.com")]
            )
        )
    )
    usable_child.save()
    stdout = dump_crl(ca=usable_child)
    assert_crl(
        stdout,
        encoding=Encoding.PEM,
        expires=86400,
        signer=usable_child,
        idp=None,
        algorithm=usable_child.algorithm,
    )


def test_disabled(usable_root: CertificateAuthority) -> None:
    """Test creating a CRL with a disabled CA."""
    usable_root.enabled = False
    usable_root.save()

    stdout = dump_crl(ca=usable_root, scope="user")
    expected_idp = get_idp(full_name=idp_full_name(usable_root), only_contains_user_certs=True)
    assert_crl(stdout, signer=usable_root, algorithm=usable_root.algorithm, idp=expected_idp)


@pytest.mark.parametrize("reason", list(x509.ReasonFlags))
def test_revoked_with_reason(
    usable_root: CertificateAuthority, root_cert: Certificate, reason: x509.ReasonFlags
) -> None:
    """Test revoked certificates."""
    idp = get_idp(full_name=idp_full_name(usable_root), only_contains_user_certs=True)
    root_cert.revoke(reason=reason)  # type: ignore[arg-type]

    stdout = dump_crl(ca=usable_root, scope="user")

    # unspecified is not included (see RFC 5280, 5.3.1)
    if reason == x509.ReasonFlags.unspecified:
        entry_extensions = None
    else:
        reason_ext: x509.Extension[x509.ExtensionType] = x509.Extension(
            oid=CRLEntryExtensionOID.CRL_REASON, critical=False, value=x509.CRLReason(reason)
        )
        entry_extensions = ([reason_ext],)

    assert_crl(
        stdout,
        [root_cert],
        signer=usable_root,
        algorithm=usable_root.algorithm,
        idp=idp,
        entry_extensions=entry_extensions,
    )


def test_compromised_timestamp(usable_root: CertificateAuthority, root_cert: Certificate) -> None:
    """Test creating a CRL with a compromised cert with a compromised timestamp."""
    idp = get_idp(full_name=idp_full_name(usable_root), only_contains_user_certs=True)
    stamp = timezone.now().replace(microsecond=0) - timedelta(10)
    root_cert.revoke(compromised=stamp)

    invalidity_date = x509.Extension(
        oid=CRLEntryExtensionOID.INVALIDITY_DATE,
        critical=False,
        value=x509.InvalidityDate(stamp.replace(tzinfo=None)),
    )
    stdout = dump_crl(ca=usable_root, scope="user")
    assert_crl(
        stdout,
        [root_cert],
        signer=usable_root,
        algorithm=usable_root.algorithm,
        idp=idp,
        entry_extensions=([invalidity_date],),
    )


def test_ca_crl(usable_root: CertificateAuthority, child: CertificateAuthority) -> None:
    """Test creating a CA CRL."""
    stdout = dump_crl(ca=usable_root, scope="ca")
    idp = get_idp(only_contains_ca_certs=True)
    assert_crl(stdout, signer=usable_root, algorithm=usable_root.algorithm, idp=idp)

    # revoke the CA and see if it's there
    child.revoke()
    assert_revoked(child)
    stdout = dump_crl(ca=usable_root, scope="ca")
    assert_crl(stdout, [child], signer=usable_root, algorithm=usable_root.algorithm, idp=idp, crl_number=1)


def test_hash_algorithm_not_allowed(ed_ca: CertificateAuthority) -> None:
    """Test creating a CRL with a hash algorithm and for a CA that does not allow it."""
    with assert_command_error(rf"^{ed_ca.key_type} keys do not allow an algorithm for signing\.$"):
        dump_crl(ca=ed_ca, algorithm=hashes.SHA512())


def test_unknown_error(usable_root: CertificateAuthority) -> None:
    """Test that creating a CRL fails for an unknown reason."""
    method = "django_ca.models.CertificateAuthority.get_crl"
    with mock.patch(method, side_effect=Exception("foo")), assert_command_error("foo"):
        dump_crl(ca=usable_root)


def test_model_validation_error(root: CertificateAuthority) -> None:
    """Test model validation is tested properly.

    NOTE: This example is contrived for the default backend, as the type of the password would already be
    checked by argparse. Other backends however might have other validation mechanisms.
    """
    with assert_command_error(r"^password: Input should be a valid bytes$"):
        dump_crl(ca=root, password=123)
