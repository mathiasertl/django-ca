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

"""Test the dump_cert management command."""

import os
import re
from io import BytesIO

from cryptography.hazmat.primitives.serialization import Encoding

from django.test import TestCase

from .. import ca_settings
from .base import override_tmpcadir
from .base.mixins import TestCaseMixin


class DumpCertTestCase(TestCaseMixin, TestCase):
    """Main test class for this command."""

    load_cas = ("root",)
    load_certs = ("root-cert",)

    def test_basic(self) -> None:
        """Basic test of this command."""
        stdout, stderr = self.cmd("dump_cert", self.cert.serial, stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b"")
        self.assertEqual(stdout.decode(), self.cert.pub.pem)

    def test_format(self) -> None:
        """Test various formats."""
        for encoding in [Encoding.PEM, Encoding.DER]:
            stdout, stderr = self.cmd(
                "dump_cert", self.cert.serial, format=encoding, stdout=BytesIO(), stderr=BytesIO()
            )
            self.assertEqual(stderr, b"")
            self.assertEqual(stdout, self.cert.pub.encode(encoding))

    def test_explicit_stdout(self) -> None:
        """Test writing to stdout."""
        stdout, stderr = self.cmd("dump_cert", self.cert.serial, "-", stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b"")
        self.assertEqual(stdout.decode(), self.cert.pub.pem)

    def test_bundle(self) -> None:
        """Test getting the bundle."""
        stdout, stderr = self.cmd(
            "dump_cert", self.cert.serial, bundle=True, stdout=BytesIO(), stderr=BytesIO()
        )
        self.assertEqual(stderr, b"")
        self.assertEqual(stdout.decode(), self.cert.pub.pem + self.ca.pub.pem)

    @override_tmpcadir()
    def test_file_output(self) -> None:
        """Test writing to a file."""
        path = os.path.join(ca_settings.CA_DIR, "test_cert.pem")
        stdout, stderr = self.cmd("dump_cert", self.cert.serial, path, stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b"")
        self.assertEqual(stdout, b"")

        with open(path, encoding="ascii") as stream:
            self.assertEqual(stream.read(), self.cert.pub.pem)

    def test_errors(self) -> None:
        """Test some error conditions."""
        path = os.path.join(ca_settings.CA_DIR, "does-not-exist", "test_cert.pem")
        msg = rf"^\[Errno 2\] No such file or directory: '{re.escape(path)}'$"
        with self.assertCommandError(msg):
            self.cmd("dump_cert", self.cert.serial, path, stdout=BytesIO(), stderr=BytesIO())

        with self.assertCommandError(r"^Cannot dump bundle when using DER format\.$"):
            self.cmd(
                "dump_cert",
                self.cert.serial,
                format=Encoding.DER,
                bundle=True,
                stdout=BytesIO(),
                stderr=BytesIO(),
            )
