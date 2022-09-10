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

"""Test the dump_crl management command."""

import os
import re
from datetime import timedelta
from io import BytesIO

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import CRLEntryExtensionOID

from django.test import TestCase
from django.utils import timezone

from freezegun import freeze_time

from .. import ca_settings
from ..models import Certificate, CertificateAuthority
from .base import certs, override_settings, override_tmpcadir, timestamps
from .base.mixins import TestCaseMixin


@freeze_time(timestamps["everything_valid"])
class DumpCRLTestCase(TestCaseMixin, TestCase):
    """Test the dump_crl management command."""

    default_ca = "root"
    load_cas = (
        "root",
        "child",
        "pwd",
    )
    load_certs = ("root-cert",)

    @override_tmpcadir()
    def test_basic(self) -> None:
        """Test basic creation of a CRL."""

        stdout, stderr = self.cmd("dump_crl", ca=self.ca, scope="user", stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b"")

        crl = x509.load_pem_x509_crl(stdout)
        self.assertIsInstance(crl.signature_hash_algorithm, hashes.SHA512)
        self.assertEqual(list(crl), [])

    @override_tmpcadir()
    def test_file(self) -> None:
        """Test dumping to a file."""

        path = os.path.join(ca_settings.CA_DIR, "crl-test.crl")
        stdout, stderr = self.cmd(
            "dump_crl", path, ca=self.ca, scope="user", stdout=BytesIO(), stderr=BytesIO()
        )
        self.assertEqual(stdout, b"")
        self.assertEqual(stderr, b"")

        with open(path, "rb") as stream:
            crl = x509.load_pem_x509_crl(stream.read())
        self.assertIsInstance(crl.signature_hash_algorithm, hashes.SHA512)
        self.assertEqual(list(crl), [])

        # test an output path that doesn't exist
        path = os.path.join(ca_settings.CA_DIR, "test", "crl-test.crl")

        with self.assertCommandError(rf"^\[Errno 2\] No such file or directory: '{re.escape(path)}'$"):
            self.cmd("dump_crl", path, ca=self.ca, scope="user", stdout=BytesIO(), stderr=BytesIO())

    @override_tmpcadir()
    def test_password(self) -> None:
        """Test creating a CRL with a CA with a password."""

        ca = self.cas["pwd"]

        # Giving no password raises a CommandError
        with self.assertCommandError("^Password was not given but private key is encrypted$"):
            self.cmd("dump_crl", ca=ca, scope="user")

        # False password
        ca = CertificateAuthority.objects.get(pk=ca.pk)
        with self.assertCommandError(self.re_false_password):
            self.cmd("dump_crl", ca=ca, scope="user", password=b"wrong")

        stdout, stderr = self.cmd(
            "dump_crl",
            ca=ca,
            scope="user",
            password=certs["pwd"]["password"],
            stdout=BytesIO(),
            stderr=BytesIO(),
        )
        self.assertEqual(stderr, b"")

        crl = x509.load_pem_x509_crl(stdout)
        self.assertIsInstance(crl.signature_hash_algorithm, hashes.SHA512)
        self.assertEqual(list(crl), [])

    @override_tmpcadir()
    def test_scope_none(self) -> None:
        """Test behavior of CRLs when they have no scope."""

        # For Root CAs, there should not be an IssuingDistributionPoint extension in this case.
        root = self.cas["root"]
        stdout, stderr = self.cmd("dump_crl", ca=root, scope=None, stdout=BytesIO(), stderr=BytesIO())
        self.assertCRL(stdout, encoding=Encoding.PEM, expires=86400, signer=root, idp=None)
        self.assertEqual(stderr, b"")

        # ... but the child CA should have one
        child = self.cas["child"]
        idp = self.get_idp(full_name=self.get_idp_full_name(child))
        stdout, stderr = self.cmd("dump_crl", ca=child, scope=None, stdout=BytesIO(), stderr=BytesIO())
        self.assertCRL(stdout, encoding=Encoding.PEM, expires=86400, signer=child, idp=idp)
        self.assertEqual(stderr, b"")

    @override_tmpcadir()
    def test_include_issuing_distribution_point(self) -> None:
        """Test forcing the inclusion of the IssuingDistributionPoint extension.

        Note: The only case where it is not included is for CRLs for root CAs with no scope, in which case not
        enough information is available to even add the extension, so the test here asserts that the call
        raises an extension.
        """

        root = self.cas["root"]
        self.assertE2ECommandError(
            ["dump_crl", f"--ca={root.serial}", "--include-issuing-distribution-point"],
            b"Cannot add IssuingDistributionPoint extension to CRLs with no scope for root CAs.",
        )

    @override_tmpcadir()
    def test_exclude_issuing_distribution_point(self) -> None:
        """Test forcing the exclusion of the IssuingDistributionPoint extension."""

        # For Root CAs, there should not be an IssuingDistributionPoint extension, test that forced exclusion
        # does not break this.
        root = self.cas["root"]
        stdout, stderr = self.cmd_e2e(
            [
                "dump_crl",
                f"--ca={root.serial}",
                "--exclude-issuing-distribution-point",
            ],
            stdout=BytesIO(),
            stderr=BytesIO(),
        )
        self.assertCRL(stdout, encoding=Encoding.PEM, expires=86400, signer=root, idp=None)
        self.assertEqual(stderr, b"")

        child = self.cas["child"]  # CRL for child CA would normally include extension
        stdout, stderr = self.cmd_e2e(
            [
                "dump_crl",
                f"--ca={child.serial}",
                "--exclude-issuing-distribution-point",
            ],
            stdout=BytesIO(),
            stderr=BytesIO(),
        )
        self.assertCRL(stdout, encoding=Encoding.PEM, expires=86400, signer=child, idp=None)
        self.assertEqual(stderr, b"")

    @override_tmpcadir()
    def test_disabled(self) -> None:
        """Test creating a CRL with a disabled CA."""

        ca = self.cas["root"]
        self.assertIsNotNone(ca.key(password=None))
        ca.enabled = False
        ca.save()

        stdout, stderr = self.cmd("dump_crl", ca=ca, scope="user", stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b"")

        crl = x509.load_pem_x509_crl(stdout)
        self.assertIsInstance(crl.signature_hash_algorithm, hashes.SHA512)
        self.assertEqual(list(crl), [])

    @override_tmpcadir()
    def test_revoked(self) -> None:
        """Test revoked certificates

        NOTE: freeze time because expired certs are not in a CRL.
        """

        self.cert.revoke()
        stdout, stderr = self.cmd("dump_crl", ca=self.ca, scope="user", stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b"")

        crl = x509.load_pem_x509_crl(stdout)
        self.assertIsInstance(crl.signature_hash_algorithm, hashes.SHA512)
        self.assertEqual(len(list(crl)), 1)
        self.assertEqual(crl[0].serial_number, self.cert.pub.loaded.serial_number)
        self.assertEqual(len(crl[0].extensions), 0)

        # try all possible reasons
        for reason in [r[0] for r in Certificate.REVOCATION_REASONS if r[0]]:
            self.cert.revoked_reason = reason
            self.cert.save()

            stdout, stderr = self.cmd(
                "dump_crl", ca=self.ca, scope="user", stdout=BytesIO(), stderr=BytesIO()
            )
            crl = x509.load_pem_x509_crl(stdout)
            self.assertIsInstance(crl.signature_hash_algorithm, hashes.SHA512)
            self.assertEqual(len(list(crl)), 1)
            self.assertEqual(crl[0].serial_number, self.cert.pub.loaded.serial_number)

            # unspecified is not included (see RFC 5280, 5.3.1)
            if reason != "unspecified":
                self.assertEqual(crl[0].extensions[0].value.reason.name, reason)

    @override_tmpcadir()
    def test_compromised(self) -> None:
        """Test creating a CRL with a compromized cert."""

        stamp = timezone.now().replace(microsecond=0) - timedelta(10)
        self.cert.revoke(compromised=stamp)

        stdout, stderr = self.cmd("dump_crl", ca=self.ca, scope="user", stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b"")

        crl = x509.load_pem_x509_crl(stdout)
        self.assertIsInstance(crl.signature_hash_algorithm, hashes.SHA512)
        self.assertEqual(len(list(crl)), 1)
        self.assertEqual(crl[0].serial_number, self.cert.pub.loaded.serial_number)
        self.assertEqual(len(crl[0].extensions), 1)
        self.assertEqual(crl[0].extensions[0].oid, CRLEntryExtensionOID.INVALIDITY_DATE)
        self.assertEqual(crl[0].extensions[0].value.invalidity_date, stamp.replace(tzinfo=None))

    @override_tmpcadir()
    def test_ca_crl(self) -> None:
        """Test creating a CA CRL.

        NOTE: freeze_time() b/c it does not work for expired CAs.
        """

        child = self.cas["child"]
        self.assertIsNotNone(child.key(password=None))
        self.assertNotRevoked(child)

        stdout, stderr = self.cmd("dump_crl", ca=self.ca, scope="ca", stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b"")

        crl = x509.load_pem_x509_crl(stdout)
        self.assertIsInstance(crl.signature_hash_algorithm, hashes.SHA512)
        self.assertEqual(list(crl), [])

        # revoke the CA and see if it's there
        child.revoke()
        self.assertRevoked(child)
        stdout, stderr = self.cmd("dump_crl", ca=self.ca, scope="ca", stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b"")

        crl = x509.load_pem_x509_crl(stdout)
        self.assertIsInstance(crl.signature_hash_algorithm, hashes.SHA512)
        self.assertEqual(len(list(crl)), 1)
        self.assertEqual(crl[0].serial_number, child.pub.loaded.serial_number)
        self.assertEqual(len(crl[0].extensions), 0)

    @override_tmpcadir()
    def test_error(self) -> None:
        """Test that creating a CRL fails for an unknown reason."""

        method = "django_ca.models.CertificateAuthority.get_crl"
        with self.patch(method, side_effect=Exception("foo")), self.assertCommandError("foo"):
            self.cmd("dump_crl", ca=self.ca, stdout=BytesIO(), stderr=BytesIO())


@override_settings(USE_TZ=True)
class DumpCRLWithTZTestCase(DumpCRLTestCase):
    """Test the dump_crl management command with timezone support."""
