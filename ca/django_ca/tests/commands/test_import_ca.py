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

"""Test the import_ca management command."""

import typing
from pathlib import Path
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from django.test import TestCase

import pytest
from freezegun import freeze_time

from django_ca import ca_settings
from django_ca.key_backends.storages import StoragesBackend, UsePrivateKeyOptions
from django_ca.models import CertificateAuthority
from django_ca.tests.base.assertions import assert_command_error, assert_signature
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS
from django_ca.tests.base.mixins import TestCaseMixin
from django_ca.tests.base.utils import (
    authority_information_access,
    cmd,
    cmd_e2e,
    crl_distribution_points,
    distribution_point,
    issuer_alternative_name,
    override_tmpcadir,
    uri,
)


def import_ca(
    name: str, key_path: Optional[Path] = None, pem_path: Optional[Path] = None, **kwargs: Any
) -> None:
    """Execute the dump_crl command."""
    key_path = key_path or CERT_DATA["root"]["key_path"]
    pem_path = pem_path or CERT_DATA["root"]["pub_path"]
    out, err = cmd("import_ca", name, key_path, pem_path, **kwargs)
    assert out == ""
    assert err == ""


def import_ca_e2e(hostname: str, *args: str) -> CertificateAuthority:
    """Shortcut for running the import_ca command."""
    key_path = str(CERT_DATA["root"]["key_path"])
    pem_path = str(CERT_DATA["root"]["pub_path"])

    out, err = cmd_e2e(["import_ca", hostname, *args, key_path, pem_path])
    assert out == ""
    assert err == ""

    return CertificateAuthority.objects.get(name=hostname)


class ImportCATest(TestCaseMixin, TestCase):
    """Test the import_ca management command."""

    @override_tmpcadir()
    @freeze_time(TIMESTAMPS["everything_valid"])
    def test_basic(self) -> None:
        """Test basic import command.

        Note: freeze time because we verify the certificate here.
        """
        cas = {
            name: data for name, data in CERT_DATA.items() if data["type"] == "ca" and data.get("key_path")
        }

        for name, data in cas.items():
            key_path = CERT_DATA[name]["key_path"]
            pem_path = CERT_DATA[name]["pub_path"]
            out, err = cmd("import_ca", name, key_path, pem_path, import_password=data.get("password"))

            assert out == ""
            assert err == ""

            ca: CertificateAuthority = CertificateAuthority.objects.get(name=name)
            ca.full_clean()  # assert e.g. max_length in serials

            if not data.get("parent"):
                assert_signature([ca], ca)
            assert ca.pub.loaded.version == x509.Version.v3

            # test the private key
            # NOTE: password is always None since we don't encrypt the stored key with --password
            ca_key = ca.key_backend.get_key(  # type: ignore[attr-defined]  # we assume StoragesBackend
                ca, UsePrivateKeyOptions(password=None)
            )
            if data["key_type"] == "EC":
                key = typing.cast(ec.EllipticCurvePrivateKey, ca_key)
                self.assertIsInstance(key, ec.EllipticCurvePrivateKey)
            elif data["key_type"] == "RSA":
                key = typing.cast(rsa.RSAPrivateKey, ca_key)  # type: ignore[assignment]
                self.assertIsInstance(key, rsa.RSAPrivateKey)
            elif data["key_type"] == "DSA":
                key = typing.cast(dsa.DSAPrivateKey, ca_key)  # type: ignore[assignment]
                self.assertIsInstance(key, dsa.DSAPrivateKey)
            elif data["key_type"] == "Ed25519":
                key = typing.cast(ed25519.Ed25519PrivateKey, ca_key)  # type: ignore[assignment]
                assert isinstance(key, ed25519.Ed25519PrivateKey)
            elif data["key_type"] == "Ed448":
                key = typing.cast(ed448.Ed448PrivateKey, ca_key)  # type: ignore[assignment]
                assert isinstance(key, ed448.Ed448PrivateKey)
            else:
                raise ValueError(f"CA with unknown key type encountered: {data['key_type']}")

            if data["key_type"] not in ("EC", "Ed25519", "Ed448"):
                self.assertEqual(key.key_size, data["key_size"])
            self.assertEqual(ca.serial, data["serial"])

            self.assertIs(ca.acme_enabled, False)
            self.assertIs(ca.acme_registration, True)
            self.assertEqual(ca.acme_profile, ca_settings.CA_DEFAULT_PROFILE)
            self.assertIs(ca.acme_requires_contact, True)
            self.assertIs(ca.api_enabled, False)

    @override_tmpcadir()
    @freeze_time(TIMESTAMPS["everything_valid"])
    def test_password(self) -> None:
        """Test importing a CA with a password for the private key.

        Note: freeze time because we verify the certificate here.
        """
        name = "testname"
        password = b"testpassword"
        key_path = CERT_DATA["root"]["key_path"]
        pem_path = CERT_DATA["root"]["pub_path"]
        out, err = cmd("import_ca", name, key_path, pem_path, password=password)

        assert out == ""
        assert err == ""

        ca = CertificateAuthority.objects.get(name=name)
        assert_signature([ca], ca)
        ca.full_clean()  # assert e.g. max_length in serials
        self.assertEqual(ca.pub.loaded.version, x509.Version.v3)

        # test the private key
        with pytest.raises(TypeError, match="^Password was not given but private key is encrypted$"):
            ca.key_backend.get_key(  # type: ignore[attr-defined]  # we assume StoragesBackend
                ca, UsePrivateKeyOptions(password=None)
            )

        ca_key = typing.cast(
            rsa.RSAPrivateKey,
            ca.key_backend.get_key(  # type: ignore[attr-defined]  # we assume StoragesBackend
                ca, UsePrivateKeyOptions(password=password)
            ),
        )

        assert isinstance(ca_key, rsa.RSAPrivateKey)
        assert ca_key.key_size == CERT_DATA["root"]["key_size"]
        assert ca.serial == CERT_DATA["root"]["serial"]

    @override_tmpcadir()
    def test_sign_options(self) -> None:
        """Test setting the sign options."""
        ca_issuer = "http://issuer.example.com"
        ocsp_responder = "http://ocsp.example.com"
        crl1 = "http://crl1.example.com"
        crl2 = "http://crl2.example.com"
        ian = "http://ian.example.com"

        ca = import_ca_e2e(
            self.hostname,
            f"--sign-ca-issuer={ca_issuer}",
            f"--sign-ocsp-responder={ocsp_responder}",
            f"--sign-issuer-alternative-name={ian}",
            f"--sign-crl-full-name={crl1}",
            f"--sign-crl-full-name={crl2}",
            # Certificate Policies extension
            "--sign-policy-identifier=1.2.3",
            "--sign-certification-practice-statement=https://cps.example.com",
            "--sign-user-notice=explicit-text",
        )

        self.assertEqual(
            ca.sign_authority_information_access,
            authority_information_access(ocsp=[uri(ocsp_responder)], ca_issuers=[uri(ca_issuer)]),
        )
        self.assertEqual(ca.sign_issuer_alternative_name, issuer_alternative_name(uri(ian)))
        self.assertEqual(
            ca.sign_crl_distribution_points,
            crl_distribution_points(distribution_point([uri(crl1), uri(crl2)])),
        )
        # Certificate Policies extension
        self.assertEqual(
            ca.sign_certificate_policies,
            self.certificate_policies(
                x509.PolicyInformation(
                    policy_identifier=x509.ObjectIdentifier("1.2.3"),
                    policy_qualifiers=[
                        "https://cps.example.com",
                        x509.UserNotice(notice_reference=None, explicit_text="explicit-text"),
                    ],
                )
            ),
        )

    @override_tmpcadir()
    def test_acme_arguments(self) -> None:
        """Test ACME arguments."""
        ca = import_ca_e2e(
            self.hostname,
            "--acme-enable",
            "--acme-disable-account-registration",
            "--acme-contact-optional",
            "--acme-profile=client",
        )
        self.assertIs(ca.acme_enabled, True)
        self.assertEqual(ca.acme_profile, "client")
        self.assertIs(ca.acme_requires_contact, False)
        self.assertIs(ca.acme_registration, False)

    @override_tmpcadir()
    def test_rest_api_arguments(self) -> None:
        """Test REST API arguments."""
        ca = import_ca_e2e(self.hostname, "--api-enable")
        self.assertIs(ca.api_enabled, True)

    @override_tmpcadir()
    def test_ocsp_responder_arguments(self) -> None:
        """Test OCSP responder arguments."""
        ca = import_ca_e2e(self.hostname, "--ocsp-responder-key-validity=10", "--ocsp-response-validity=3600")

        self.assertEqual(ca.ocsp_responder_key_validity, 10)
        self.assertEqual(ca.ocsp_response_validity, 3600)


@pytest.mark.usefixtures("tmpcadir")
@pytest.mark.usefixtures("db")
def test_key_backend_option(ca_name: str) -> None:
    """Test the --key-backend option."""
    key_path = CERT_DATA["root"]["key_path"]
    certificate_path = CERT_DATA["root"]["pub_path"]
    out, err = cmd_e2e(["import_ca", ca_name, str(key_path), str(certificate_path), "--key-backend=default"])
    assert out == ""
    assert err == ""

    ca = CertificateAuthority.objects.get(name=ca_name)
    assert ca.key_backend_alias == "default"


@pytest.mark.usefixtures("tmpcadir")
@pytest.mark.usefixtures("db")
def test_secondary_key_backend(ca_name: str) -> None:
    """Use secondary key backend with a password."""
    key_path = CERT_DATA["root"]["key_path"]
    certificate_path = CERT_DATA["root"]["pub_path"]
    out, err = cmd_e2e(
        [
            "import_ca",
            ca_name,
            str(key_path),
            str(certificate_path),
            "--key-backend=secondary",
            "--secondary-password=foobar",
            "--secondary-path=secondary-ca-path",
        ]
    )
    assert out == ""
    assert err == ""

    ca: CertificateAuthority = CertificateAuthority.objects.get(name=ca_name)
    assert ca.key_backend_alias == "secondary"
    assert ca.key_backend_options["path"].startswith("secondary-ca-path")
    assert isinstance(ca.key_backend, StoragesBackend)
    assert ca.key_backend.get_key(ca, UsePrivateKeyOptions(password="foobar"))  # type: ignore[attr-defined]


def test_bogus_public_key(ca_name: str) -> None:
    """Test importing a CA with a bogus public key."""
    key_path = CERT_DATA["root"]["key_path"]
    with assert_command_error(r"^Unable to load public key\.$"):
        import_ca(ca_name, key_path, Path(__file__).resolve())


def test_bogus_private_key(ca_name: str) -> None:
    """Test importing a CA with a bogus private key."""
    pem_path = CERT_DATA["root"]["pub_path"]
    with assert_command_error(r"^Unable to load private key\.$"):
        import_ca(ca_name, Path(__file__).resolve(), pem_path)


def test_invalid_private_key_type(tmp_path: Path, ca_name: str) -> None:
    """Test importing a CA with an invalid private key type."""
    private_key = X448PrivateKey.generate()
    private_key_der = private_key.private_bytes(
        Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
    )
    private_key_path = tmp_path / "x448.key"
    with open(private_key_path, "wb") as stream:
        stream.write(private_key_der)

    pem_path = CERT_DATA["root"]["pub_path"]
    with assert_command_error(r"^X448PrivateKey: Invalid private key type\.$"):
        import_ca(ca_name, private_key_path, pem_path)


def test_model_validation_error(ca_name: str, key_backend: StoragesBackend) -> None:
    """Test model validation is tested properly.

    NOTE: This example is contrived for the default backend, as the type of the password would already be
    checked by argparse. Other backends however might have other validation mechanisms.
    """
    with assert_command_error(r"^password: Input should be a valid bytes$"):
        import_ca(ca_name, key_backend=key_backend, password=123)
