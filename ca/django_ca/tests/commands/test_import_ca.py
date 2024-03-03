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

import os
import tempfile
import typing
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from django.test import TestCase

import pytest
from freezegun import freeze_time

from django_ca import ca_settings
from django_ca.backends.storages import LoadPrivateKeyOptions
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
    mock_cadir,
    override_tmpcadir,
    uri,
)


class ImportCATest(TestCaseMixin, TestCase):
    """Test the import_ca management command."""

    def import_ca(self, *args: str) -> CertificateAuthority:
        """Shortcut for running the import_ca command."""
        key_path = str(CERT_DATA["root"]["key_path"])
        pem_path = str(CERT_DATA["root"]["pub_path"])

        out, err = cmd_e2e(["import_ca", self.hostname, *args, key_path, pem_path])
        self.assertEqual(out, "")
        self.assertEqual(err, "")

        return CertificateAuthority.objects.get(name=self.hostname)

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
                ca, LoadPrivateKeyOptions(password=None)
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
                ca, LoadPrivateKeyOptions(password=None)
            )

        ca_key = typing.cast(
            rsa.RSAPrivateKey,
            ca.key_backend.get_key(  # type: ignore[attr-defined]  # we assume StoragesBackend
                ca, LoadPrivateKeyOptions(password=password)
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

        ca = self.import_ca(
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
        ca = self.import_ca(
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
        ca = self.import_ca("--api-enable")
        self.assertIs(ca.api_enabled, True)

    @override_tmpcadir()
    def test_ocsp_responder_arguments(self) -> None:
        """Test OCSP responder arguments."""
        ca = self.import_ca("--ocsp-responder-key-validity=10", "--ocsp-response-validity=3600")

        self.assertEqual(ca.ocsp_responder_key_validity, 10)
        self.assertEqual(ca.ocsp_response_validity, 3600)

    def test_create_cadir(self) -> None:
        """Test importing a CA when the directory does not yet exist."""
        name = "testname"
        key_path = CERT_DATA["root"]["key_path"]
        pem_path = CERT_DATA["root"]["pub_path"]

        with tempfile.TemporaryDirectory() as tempdir:
            ca_dir = os.path.join(tempdir, "foo", "bar")
            with mock_cadir(ca_dir):
                cmd("import_ca", name, key_path, pem_path)

    @override_tmpcadir()
    def test_bogus_pub(self) -> None:
        """Test importing a CA with a bogus public key."""
        name = "testname"
        key_path = CERT_DATA["root"]["key_path"]
        with assert_command_error(r"^Unable to load public key\.$"):
            cmd("import_ca", name, key_path, Path(__file__).resolve())
        self.assertEqual(CertificateAuthority.objects.count(), 0)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_bogus_priv(self) -> None:
        """Test importing a CA with a bogus private key."""
        name = "testname"
        pem_path = CERT_DATA["root"]["pub_path"]
        with assert_command_error(r"^Unable to load private key\.$"):
            cmd("import_ca", name, Path(__file__).resolve(), pem_path)
        self.assertEqual(CertificateAuthority.objects.count(), 0)
