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

"""Test the regenerate_ocsp_keys management command."""

import typing
from collections.abc import Iterable
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from django.core.files.storage import storages
from django.test import TestCase

from django_ca.conf import model_settings
from django_ca.key_backends.storages import UsePrivateKeyOptions
from django_ca.models import Certificate, CertificateAuthority
from django_ca.tests.base.assertions import assert_command_error
from django_ca.tests.base.constants import CERT_DATA
from django_ca.tests.base.mixins import TestCaseMixin
from django_ca.tests.base.utils import cmd, cmd_e2e, override_tmpcadir
from django_ca.utils import add_colons, read_file


def regenerate_ocsp_keys(*serials: str, **kwargs: Any) -> tuple[str, str]:
    """Execute the regenerate_ocsp_keys command."""
    return cmd("regenerate_ocsp_keys", *serials, **kwargs)


class RegenerateOCSPKeyTestCase(TestCaseMixin, TestCase):
    """Main test class for this command."""

    load_cas = "__usable__"

    def setUp(self) -> None:
        super().setUp()
        self.existing_certs = list(Certificate.objects.values_list("pk", flat=True))

    def assertKey(  # pylint: disable=invalid-name
        self,
        ca: CertificateAuthority,
        key_type: Optional[type[CertificateIssuerPrivateKeyTypes]] = None,
        key_size: Optional[int] = 2048,
        password: Optional[bytes] = None,
        excludes: Optional[Iterable[int]] = None,
        elliptic_curve: type[ec.EllipticCurve] = ec.SECP256R1,
    ) -> tuple[CertificateIssuerPrivateKeyTypes, x509.Certificate]:
        """Assert that they key is present and can be read."""
        priv_path = f"ocsp/{ca.serial}.key"
        cert_path = f"ocsp/{ca.serial}.pem"

        storage = storages[model_settings.CA_DEFAULT_STORAGE_ALIAS]
        self.assertTrue(storage.exists(priv_path))
        self.assertTrue(storage.exists(cert_path))
        if key_type is None:
            ca_key = ca.key_backend.get_key(  # type: ignore[attr-defined]  # we assume StoragesBackend
                ca, UsePrivateKeyOptions(password=None)
            )
            key_type = type(ca_key)

        priv = typing.cast(
            CertificateIssuerPrivateKeyTypes, load_der_private_key(read_file(priv_path), password)
        )
        self.assertIsInstance(priv, key_type)
        if isinstance(priv, (dsa.DSAPrivateKey, rsa.RSAPrivateKey)):
            self.assertEqual(priv.key_size, key_size)
        if isinstance(priv, ec.EllipticCurvePrivateKey):
            self.assertIsInstance(priv.curve, elliptic_curve)

        cert = x509.load_pem_x509_certificate(read_file(cert_path))
        self.assertIsInstance(cert, x509.Certificate)

        cert_qs = Certificate.objects.filter(ca=ca).exclude(pk__in=self.existing_certs)

        if excludes:
            cert_qs = cert_qs.exclude(pk__in=excludes)

        db_cert = cert_qs.get()

        aia = typing.cast(
            x509.Extension[x509.AuthorityInformationAccess],
            db_cert.extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
        )

        expected_aia = x509.Extension(
            oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
            critical=ca.sign_authority_information_access.critical,  # type: ignore[union-attr]
            value=x509.AuthorityInformationAccess(
                ad
                for ad in ca.sign_authority_information_access.value  # type: ignore[union-attr]
                if ad.access_method == AuthorityInformationAccessOID.CA_ISSUERS
            ),
        )
        self.assertEqual(aia, expected_aia)

        return priv, cert

    def assertHasNoKey(self, serial: str) -> None:  # pylint: disable=invalid-name
        """Assert that the key is **not** present."""
        priv_path = f"ocsp/{serial}.key"
        cert_path = f"ocsp/{serial}.pem"
        storage = storages[model_settings.CA_DEFAULT_STORAGE_ALIAS]
        self.assertFalse(storage.exists(priv_path))
        self.assertFalse(storage.exists(cert_path))

    @override_tmpcadir(CA_USE_CELERY=False)  # CA_USE_CELERY=False is set anyway, but just to be sure
    def test_basic(self) -> None:
        """Basic test."""
        with self.mute_celery():
            stdout, stderr = cmd("regenerate_ocsp_keys", CERT_DATA["root"]["serial"])

        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        self.assertKey(self.cas["root"])

    @override_tmpcadir(CA_USE_CELERY=False)
    def test_rsa_with_key_size(self) -> None:
        """Test creating an RSA key with explicit key size."""
        with self.mute_celery():
            stdout, stderr = cmd(
                "regenerate_ocsp_keys", CERT_DATA["root"]["serial"], key_type="RSA", key_size=4096
            )

        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        self.assertKey(self.cas["root"], key_size=4096)

    @override_tmpcadir(CA_USE_CELERY=False)
    def test_ec_with_curve(self) -> None:
        """Test creating an EC key with explicit elliptic curve."""
        with self.mute_celery():
            stdout, stderr = cmd(
                "regenerate_ocsp_keys", CERT_DATA["ec"]["serial"], elliptic_curve=ec.SECP384R1()
            )

        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        self.assertKey(self.cas["ec"], elliptic_curve=ec.SECP384R1)

    @override_tmpcadir(CA_USE_CELERY=False)  # CA_USE_CELERY=False is set anyway, but just to be sure
    def test_hash_algorithm(self) -> None:
        """Test the hash algorithm option."""
        with self.mute_celery():
            stdout, stderr = cmd(
                "regenerate_ocsp_keys", CERT_DATA["root"]["serial"], "--algorithm", "SHA-256"
            )

        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        self.assertKey(self.cas["root"])

    @override_tmpcadir(CA_USE_CELERY=True)
    def test_with_celery(self) -> None:
        """Basic test."""
        with self.mute_celery(
            (
                (
                    tuple(),
                    {
                        "serial": CERT_DATA["root"]["serial"],
                        "key_backend_options": {"password": None},
                        "profile": "ocsp",
                        "expires": 172800,
                        "algorithm": "SHA-256",
                        "key_size": None,
                        "key_type": "RSA",
                        "elliptic_curve": None,
                        "force": False,
                        "autogenerated": True,
                    },
                ),
                {},
            ),
        ):
            stdout, stderr = cmd_e2e(
                ["regenerate_ocsp_keys", CERT_DATA["root"]["serial"], "--algorithm", "SHA-256"]
            )
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")

    @override_tmpcadir()
    def test_with_ed448_with_explicit_key_type(self) -> None:
        """Test creating an Ed448-based OCSP key for an RSA-based CA."""
        stdout, stderr = cmd_e2e(["regenerate_ocsp_keys", CERT_DATA["root"]["serial"], "--key-type", "Ed448"])
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")

        self.assertKey(self.cas["root"], key_type=ed448.Ed448PrivateKey)

    @override_tmpcadir()
    def test_all(self) -> None:
        """Test for all CAs."""
        # Delete pwd_ca, because it will fail, since we do not give a password
        self.cas["pwd"].delete()
        del self.cas["pwd"]

        stdout, stderr = cmd("regenerate_ocsp_keys")
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        for ca in self.cas.values():
            self.assertKey(ca)

    @override_tmpcadir()
    def test_overwrite(self) -> None:
        """Test overwriting pre-generated OCSP keys."""
        stdout, stderr = cmd("regenerate_ocsp_keys", CERT_DATA["root"]["serial"])
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        priv, cert = self.assertKey(self.cas["root"])

        # get list of existing certificates
        excludes = list(Certificate.objects.all().values_list("pk", flat=True))

        # write again
        stdout, stderr = cmd("regenerate_ocsp_keys", CERT_DATA["root"]["serial"], force=True)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        new_priv, new_cert = self.assertKey(self.cas["root"], excludes=excludes)

        # Key/Cert should now be different
        self.assertNotEqual(priv, new_priv)
        self.assertNotEqual(cert, new_cert)

    @override_tmpcadir()
    def test_wrong_serial(self) -> None:
        """Try passing an unknown CA."""
        serial = "ZZZZZ"
        stdout, stderr = cmd("regenerate_ocsp_keys", serial, no_color=True)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "0Z:ZZ:ZZ: Unknown CA.\n")
        self.assertHasNoKey(serial)

    @override_tmpcadir(CA_PROFILES={"ocsp": None})
    def test_no_ocsp_profile(self) -> None:
        """Try when there is no OCSP profile."""
        with assert_command_error(r"^ocsp: Undefined profile\.$"):
            cmd("regenerate_ocsp_keys", CERT_DATA["root"]["serial"])
        self.assertHasNoKey(CERT_DATA["root"]["serial"])

    def test_no_private_key(self) -> None:
        """Try when there is no private key."""
        ca = self.cas["root"]
        stdout, stderr = cmd("regenerate_ocsp_keys", ca.serial, no_color=True)
        assert stdout == ""
        assert stderr == f"{add_colons(ca.serial)}: CA has no private key.\n"
        self.assertHasNoKey(ca.serial)

        # and in quiet mode
        stdout, stderr = cmd("regenerate_ocsp_keys", ca.serial, quiet=True, no_color=True)
        assert stdout == ""
        assert stderr == ""
        self.assertHasNoKey(ca.serial)


def test_model_validation_error(root: CertificateAuthority) -> None:
    """Test model validation is tested properly.

    NOTE: This example is contrived for the default backend, as the type of the password would already be
    checked by argparse. Other backends however might have other validation mechanisms.
    """
    with assert_command_error(r"^password: Input should be a valid bytes$"):
        regenerate_ocsp_keys(root.serial, password=123)
