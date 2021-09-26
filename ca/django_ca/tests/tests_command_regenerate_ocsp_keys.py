# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca.  If not,
# see <http://www.gnu.org/licenses/>

"""Test the regenerate_ocsp_keys management command."""

import typing

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from django.test import TestCase

from ..models import Certificate
from ..models import CertificateAuthority
from ..typehints import PrivateKeyTypes
from ..utils import add_colons
from ..utils import ca_storage
from .base import certs
from .base import override_tmpcadir
from .base.mixins import TestCaseMixin


class RegenerateOCSPKeyTestCase(TestCaseMixin, TestCase):
    """Main test class for this command."""

    load_cas = "__usable__"

    def setUp(self) -> None:
        super().setUp()
        self.existing_certs = list(Certificate.objects.values_list("pk", flat=True))

    def assertKey(  # pylint: disable=invalid-name
        self,
        ca: CertificateAuthority,
        key_type: typing.Type[PrivateKeyTypes] = RSAPrivateKey,
        password: typing.Optional[bytes] = None,
        excludes: typing.Optional[typing.Iterable[int]] = None,
    ) -> typing.Tuple[PrivateKeyTypes, x509.Certificate]:
        """Assert that they key ispresent and can be read."""
        priv_path = f"ocsp/{ca.serial}.key"
        cert_path = f"ocsp/{ca.serial}.pem"

        self.assertTrue(ca_storage.exists(priv_path))
        self.assertTrue(ca_storage.exists(cert_path))

        with ca_storage.open(priv_path, "rb") as stream:
            priv = stream.read()
        priv = load_pem_private_key(priv, password, default_backend())
        self.assertIsInstance(priv, key_type)

        with ca_storage.open(cert_path, "rb") as stream:
            cert = stream.read()
        cert = x509.load_pem_x509_certificate(cert, default_backend())
        self.assertIsInstance(cert, x509.Certificate)

        cert_qs = Certificate.objects.filter(ca=ca).exclude(pk__in=self.existing_certs)

        if excludes:
            cert_qs = cert_qs.exclude(pk__in=excludes)

        db_cert = cert_qs.get()
        self.assertIsNotNone(db_cert.authority_information_access)
        # NOTE: mypy does not see that aia is *not* none due to above check
        self.assertEqual(db_cert.authority_information_access.ocsp, [])  # type: ignore[union-attr]

        return priv, cert

    def assertHasNoKey(self, serial: str) -> None:  # pylint: disable=invalid-name
        """Assert that the key is **not** present."""
        priv_path = f"ocsp/{serial}.key"
        cert_path = f"ocsp/{serial}.pem"
        self.assertFalse(ca_storage.exists(priv_path))
        self.assertFalse(ca_storage.exists(cert_path))

    @override_tmpcadir(CA_USE_CELERY=False)  # CA_USE_CELERY=False is set anyway, but just to be sure
    def test_basic(self) -> None:
        """Basic test."""
        with self.mute_celery():
            stdout, stderr = self.cmd("regenerate_ocsp_keys", certs["root"]["serial"])

        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        self.assertKey(self.cas["root"])

    @override_tmpcadir(CA_USE_CELERY=True)
    def test_with_celery(self) -> None:
        """Basic test."""
        with self.mute_celery(
            (
                (
                    (certs["root"]["serial"],),
                    {
                        "profile": "ocsp",
                        "expires": 172800.0,
                        "algorithm": "sha512",
                        "key_size": 1024,
                        "key_type": "RSA",
                        "ecc_curve": "secp256r1",
                        "password": None,
                    },
                ),
                {},
            ),
        ):
            stdout, stderr = self.cmd("regenerate_ocsp_keys", certs["root"]["serial"])
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")

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
        stdout, stderr = self.cmd("regenerate_ocsp_keys", certs["root"]["serial"])
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        priv, cert = self.assertKey(self.cas["root"])

        # get list of existing certificates
        excludes = list(Certificate.objects.all().values_list("pk", flat=True))

        # write again
        stdout, stderr = self.cmd("regenerate_ocsp_keys", certs["root"]["serial"])
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
            self.cmd("regenerate_ocsp_keys", certs["root"]["serial"])
        self.assertHasNoKey(certs["root"]["serial"])

    @override_tmpcadir()
    def test_no_private_key(self) -> None:
        """Try when there is no private key."""
        ca = self.cas["root"]
        ca_storage.delete(ca.private_key_path)
        stdout, stderr = self.cmd("regenerate_ocsp_keys", ca.serial, no_color=True)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, f"{add_colons(ca.serial)}: CA has no private key.\n")
        self.assertHasNoKey(ca.serial)

        # and in quiet mode
        stdout, stderr = self.cmd("regenerate_ocsp_keys", ca.serial, quiet=True, no_color=True)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "")
        self.assertHasNoKey(ca.serial)
