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
from typing import Iterable, Optional, Tuple, Type

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from django.core.files.storage import storages
from django.test import TestCase

from django_ca.models import Certificate, CertificateAuthority
from django_ca.tests.base.constants import CERT_DATA
from django_ca.tests.base.mixins import TestCaseMixin
from django_ca.tests.base.utils import override_tmpcadir
from django_ca.utils import add_colons, file_exists, read_file


class RegenerateOCSPKeyTestCase(TestCaseMixin, TestCase):
    """Main test class for this command."""

    load_cas = "__usable__"

    def setUp(self) -> None:
        super().setUp()
        self.existing_certs = list(Certificate.objects.values_list("pk", flat=True))

    def assertKey(  # pylint: disable=invalid-name
        self,
        ca: CertificateAuthority,
        key_type: Optional[Type[CertificateIssuerPrivateKeyTypes]] = None,
        key_size: Optional[int] = 2048,
        password: Optional[bytes] = None,
        excludes: Optional[Iterable[int]] = None,
        elliptic_curve: Type[ec.EllipticCurve] = ec.SECP256R1,
    ) -> Tuple[CertificateIssuerPrivateKeyTypes, x509.Certificate]:
        """Assert that they key is present and can be read."""
        priv_path = f"ocsp/{ca.serial}.key"
        cert_path = f"ocsp/{ca.serial}.pem"

        self.assertTrue(file_exists(priv_path))
        self.assertTrue(file_exists(cert_path))
        if key_type is None:
            key_type = type(ca.key())

        priv = typing.cast(
            CertificateIssuerPrivateKeyTypes, load_pem_private_key(read_file(priv_path), password)
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
        self.assertFalse(file_exists(priv_path))
        self.assertFalse(file_exists(cert_path))

    @override_tmpcadir(CA_USE_CELERY=False)  # CA_USE_CELERY=False is set anyway, but just to be sure
    def test_basic(self) -> None:
        """Basic test."""
        with self.mute_celery():
            stdout, stderr = self.cmd("regenerate_ocsp_keys", CERT_DATA["root"]["serial"])

        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        self.assertKey(self.cas["root"])

    @override_tmpcadir(CA_USE_CELERY=False)
    def test_rsa_with_key_size(self) -> None:
        """Test creating an RSA key with explicit key size."""
        with self.mute_celery():
            stdout, stderr = self.cmd(
                "regenerate_ocsp_keys", CERT_DATA["root"]["serial"], key_type="RSA", key_size=4096
            )

        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        self.assertKey(self.cas["root"], key_size=4096)

    @override_tmpcadir(CA_USE_CELERY=False)
    def test_ec_with_curve(self) -> None:
        """Test creating an EC key with explicit elliptic curve."""
        with self.mute_celery():
            stdout, stderr = self.cmd(
                "regenerate_ocsp_keys", CERT_DATA["ec"]["serial"], elliptic_curve=ec.SECP384R1()
            )

        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        self.assertKey(self.cas["ec"], elliptic_curve=ec.SECP384R1)

    @override_tmpcadir(CA_USE_CELERY=False)  # CA_USE_CELERY=False is set anyway, but just to be sure
    def test_hash_algorithm(self) -> None:
        """Test the hash algorithm option."""
        with self.mute_celery():
            stdout, stderr = self.cmd(
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
                    (CERT_DATA["root"]["serial"],),
                    {
                        "profile": "ocsp",
                        "expires": 172800.0,
                        "algorithm": "SHA-256",
                        "key_size": None,
                        "key_type": "RSA",
                        "elliptic_curve": None,
                        "password": None,
                        "force": False,
                    },
                ),
                {},
            ),
        ):
            stdout, stderr = self.cmd_e2e(
                ["regenerate_ocsp_keys", CERT_DATA["root"]["serial"], "--algorithm", "SHA-256"]
            )
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")

    @override_tmpcadir()
    def test_with_ed448_with_explicit_key_type(self) -> None:
        """Test creating an Ed448-based OCSP key for an RSA-based CA."""
        stdout, stderr = self.cmd_e2e(
            ["regenerate_ocsp_keys", CERT_DATA["root"]["serial"], "--key-type", "Ed448"]
        )
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")

        self.assertKey(self.cas["root"], key_type=ed448.Ed448PrivateKey)

    @override_tmpcadir()
    def test_all(self) -> None:
        """Test for all CAs."""
        # Delete pwd_ca, because it will fail, since we do not give a password
        self.cas["pwd"].delete()
        del self.cas["pwd"]

        stdout, stderr = self.cmd("regenerate_ocsp_keys")
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        for ca in self.cas.values():
            self.assertKey(ca)

    @override_tmpcadir()
    def test_overwrite(self) -> None:
        """Test overwriting pre-generated OCSP keys."""
        stdout, stderr = self.cmd("regenerate_ocsp_keys", CERT_DATA["root"]["serial"])
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        priv, cert = self.assertKey(self.cas["root"])

        # get list of existing certificates
        excludes = list(Certificate.objects.all().values_list("pk", flat=True))

        # write again
        stdout, stderr = self.cmd("regenerate_ocsp_keys", CERT_DATA["root"]["serial"], force=True)
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
        stdout, stderr = self.cmd("regenerate_ocsp_keys", serial, no_color=True)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "0Z:ZZ:ZZ: Unknown CA.\n")
        self.assertHasNoKey(serial)

    @override_tmpcadir(CA_PROFILES={"ocsp": None})
    def test_no_ocsp_profile(self) -> None:
        """Try when there is no OCSP profile."""
        with self.assertCommandError(r"^ocsp: Undefined profile\.$"):
            self.cmd("regenerate_ocsp_keys", CERT_DATA["root"]["serial"])
        self.assertHasNoKey(CERT_DATA["root"]["serial"])

    @override_tmpcadir()
    def test_no_private_key(self) -> None:
        """Try when there is no private key."""
        ca = self.cas["root"]
        storages["django-ca"].delete(ca.private_key_path)
        stdout, stderr = self.cmd("regenerate_ocsp_keys", ca.serial, no_color=True)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, f"{add_colons(ca.serial)}: CA has no private key.\n")
        self.assertHasNoKey(ca.serial)

        # and in quiet mode
        stdout, stderr = self.cmd("regenerate_ocsp_keys", ca.serial, quiet=True, no_color=True)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        self.assertHasNoKey(ca.serial)
