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
# see <http://www.gnu.org/licenses/>.

"""Test the import_ca management command."""

import os
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from django.conf import settings
from django.test import TestCase

from freezegun import freeze_time

from ..models import CertificateAuthority
from .base import certs
from .base import mock_cadir
from .base import override_tmpcadir
from .base import timestamps
from .base.mixins import TestCaseMixin


class ImportCATest(TestCaseMixin, TestCase):
    """Test the import_ca management command."""

    @override_tmpcadir()
    @freeze_time(timestamps["everything_valid"])
    def test_basic(self) -> None:
        """Test basic import command.

        Note: freeze time because we verify the certificate here.
        """

        cas = {
            name: data for name, data in certs.items() if data["type"] == "ca" and data.get("key_filename")
        }

        for name, data in cas.items():
            if data.get("password"):
                continue

            key_path = os.path.join(settings.FIXTURES_DIR, data["key_filename"])
            pem_path = os.path.join(settings.FIXTURES_DIR, data["pub_filename"])
            out, err = self.cmd("import_ca", name, key_path, pem_path)

            self.assertEqual(out, "")
            self.assertEqual(err, "")

            ca = CertificateAuthority.objects.get(name=name)
            ca.full_clean()  # assert e.g. max_length in serials

            if not data.get("parent"):
                self.assertSignature([ca], ca)
            self.assertEqual(ca.pub.loaded.version, x509.Version.v3)

            # test the private key
            key = ca.key(data["password"])
            self.assertIsInstance(key, RSAPrivateKey)
            self.assertEqual(key.key_size, data["key_size"])
            self.assertEqual(ca.serial, data["serial"])

    @override_tmpcadir()
    @freeze_time(timestamps["everything_valid"])
    def test_der(self) -> None:
        """Test importing a der key.

        Note: freeze time because we verify the certificate here.
        """

        cas = {
            name: data
            for name, data in certs.items()
            if data.get("key_der_filename") and data["type"] == "ca"
        }

        for name, data in cas.items():
            if data.get("password"):
                continue

            key_path = os.path.join(settings.FIXTURES_DIR, data["key_der_filename"])
            pem_path = os.path.join(settings.FIXTURES_DIR, data["pub_der_filename"])
            out, err = self.cmd("import_ca", name, key_path, pem_path)

            self.assertEqual(out, "")
            self.assertEqual(err, "")

            ca = CertificateAuthority.objects.get(name=name)
            ca.full_clean()  # assert e.g. max_length in serials

            if not data.get("parent"):
                self.assertSignature(reversed(ca.bundle), ca)

            self.assertEqual(ca.pub.loaded.version, x509.Version.v3)

            # test the private key
            key = ca.key(None)
            self.assertIsInstance(key, RSAPrivateKey)
            self.assertEqual(key.key_size, data["key_size"])
            self.assertEqual(ca.serial, data["serial"])

    @override_tmpcadir()
    @freeze_time(timestamps["everything_valid"])
    def test_password(self) -> None:
        """Test importing a CA with a password for the private key.

        Note: freeze time because we verify the certificate here.
        """

        name = "testname"
        password = b"testpassword"
        key_path = os.path.join(settings.FIXTURES_DIR, certs["root"]["key_filename"])
        pem_path = os.path.join(settings.FIXTURES_DIR, certs["root"]["pub_filename"])
        out, err = self.cmd("import_ca", name, key_path, pem_path, password=password)

        self.assertEqual(out, "")
        self.assertEqual(err, "")

        ca = CertificateAuthority.objects.get(name=name)
        self.assertSignature([ca], ca)
        ca.full_clean()  # assert e.g. max_length in serials
        self.assertEqual(ca.pub.loaded.version, x509.Version.v3)

        # test the private key
        with self.assertRaisesRegex(TypeError, "^Password was not given but private key is encrypted$"):
            key = ca.key(None)

        key = ca.key(password)
        self.assertIsInstance(key, RSAPrivateKey)
        self.assertEqual(key.key_size, certs["root"]["key_size"])
        self.assertEqual(ca.serial, certs["root"]["serial"])

    @override_tmpcadir()
    def test_permission_denied(self) -> None:
        """Test importing a CA when we can't ready one of the files."""

        name = "testname"
        pem_path = os.path.join(settings.FIXTURES_DIR, certs["root"]["pub_filename"])
        key_path = os.path.join(settings.FIXTURES_DIR, certs["root"]["key_filename"])
        self.assertTrue(os.path.exists(key_path))  # just make sure that file exists
        self.assertTrue(os.path.exists(pem_path))  # just make sure that file exists
        os.chmod(settings.CA_DIR, 0o000)

        try:
            serial = certs["root"]["serial"].replace(":", "")
            error = rf"^{serial}\.key: Permission denied: Could not open file for writing$"
            with self.assertCommandError(error):
                self.cmd("import_ca", name, key_path, pem_path)
        finally:
            # otherwise we might not be able to remove temporary CA_DIR
            os.chmod(settings.CA_DIR, 0o755)

    def test_create_cadir(self) -> None:
        """Test importing a CA when the directory does not yet exist."""

        name = "testname"
        pem_path = os.path.join(settings.FIXTURES_DIR, certs["root"]["pub_filename"])
        key_path = os.path.join(settings.FIXTURES_DIR, certs["root"]["key_filename"])

        with tempfile.TemporaryDirectory() as tempdir:
            ca_dir = os.path.join(tempdir, "foo", "bar")
            with mock_cadir(ca_dir):
                self.cmd("import_ca", name, key_path, pem_path)

    def test_create_cadir_permission_denied(self) -> None:
        """Test importing a CA when the directory does not yet exist and we cannot create it."""

        name = "testname"
        pem_path = os.path.join(settings.FIXTURES_DIR, certs["root"]["pub_filename"])
        key_path = os.path.join(settings.FIXTURES_DIR, certs["root"]["key_filename"])

        with tempfile.TemporaryDirectory() as tempdir:
            os.chmod(tempdir, 0o000)
            ca_dir = os.path.join(tempdir, "foo", "bar")
            msg = rf"^{ca_dir}: Could not create CA_DIR: Permission denied.$"
            with mock_cadir(ca_dir), self.assertCommandError(msg):
                self.cmd("import_ca", name, key_path, pem_path)

            # removing tempdir with these permissions throws an error before python 3.8.
            os.chmod(tempdir, 0o755)  # pragma: only py<3.8

    @override_tmpcadir()
    def test_bogus_pub(self) -> None:
        """Test importing a CA with a bogus public key."""

        name = "testname"
        pem_path = os.path.join(settings.FIXTURES_DIR, __file__)
        key_path = os.path.join(settings.FIXTURES_DIR, certs["root"]["key_der_filename"])
        with self.assertCommandError(r"^Unable to load public key\.$"):
            self.cmd("import_ca", name, key_path, pem_path)
        self.assertEqual(CertificateAuthority.objects.count(), 0)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_bogus_priv(self) -> None:
        """Test importing a CA with a bogus private key."""

        name = "testname"
        pem_path = os.path.join(settings.FIXTURES_DIR, certs["root"]["pub_der_filename"])
        key_path = os.path.join(settings.FIXTURES_DIR, __file__)
        with self.assertCommandError(r"^Unable to load private key\.$"):
            self.cmd("import_ca", name, key_path, pem_path)
        self.assertEqual(CertificateAuthority.objects.count(), 0)
