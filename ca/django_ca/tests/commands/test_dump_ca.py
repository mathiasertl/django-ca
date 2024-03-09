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

"""Test the dump_ca management command."""

import os
import re
from io import BytesIO

from cryptography.hazmat.primitives.serialization import Encoding

from django.test import TestCase

from django_ca import ca_settings
from django_ca.tests.base.mixins import TestCaseMixin
from django_ca.tests.base.utils import cmd, override_tmpcadir


class DumpCATestCase(TestCaseMixin, TestCase):
    """Main test class for this command."""

    load_cas = ("root",)

    @override_tmpcadir()
    def test_basic(self) -> None:
        """Basic test of this command."""
        stdout, stderr = cmd("dump_ca", self.ca.serial, stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b"")
        self.assertEqual(stdout.decode(), self.ca.pub.pem)

    @override_tmpcadir()
    def test_format(self) -> None:
        """Test various formats."""
        for encoding in [Encoding.PEM, Encoding.DER]:
            stdout, stderr = cmd(
                "dump_ca", self.ca.serial, format=encoding, stdout=BytesIO(), stderr=BytesIO()
            )
            self.assertEqual(stderr, b"")
            self.assertEqual(stdout, self.ca.pub.encode(encoding))

    @override_tmpcadir()
    def test_explicit_stdout(self) -> None:
        """Test piping to stdout."""
        stdout, stderr = cmd("dump_ca", self.ca.serial, "-", stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b"")
        self.assertEqual(stdout.decode(), self.ca.pub.pem)

    @override_tmpcadir()
    def test_bundle(self) -> None:
        """Test getting the bundle."""
        stdout, stderr = cmd("dump_ca", self.ca.serial, "-", bundle=True, stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b"")
        self.assertEqual(stdout.decode(), self.ca.pub.pem)

        child = self.load_ca("child")
        stdout, stderr = cmd("dump_ca", child.serial, "-", bundle=True, stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b"")
        self.assertEqual(stdout.decode(), child.pub.pem + self.ca.pub.pem)

    @override_tmpcadir()
    def test_file_output(self) -> None:
        """Test writing to file."""
        path = os.path.join(ca_settings.CA_DIR, "test_ca.pem")
        stdout, stderr = cmd("dump_ca", self.ca.serial, path, stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stderr, b"")
        self.assertEqual(stdout, b"")

        with open(path, encoding="ascii") as stream:
            self.assertEqual(stream.read(), self.ca.pub.pem)

    @override_tmpcadir()
    def test_color_output_error(self) -> None:
        """Test that requesting color output throws an error."""
        with self.assertCommandError("This command does not support color output."):
            cmd("dump_ca", self.ca.serial, "/does/not/exist", force_color=True)

    @override_tmpcadir()
    def test_errors(self) -> None:
        """Test some error conditions."""
        path = os.path.join(ca_settings.CA_DIR, "does-not-exist", "test_ca.pem")
        with self.assertCommandError(rf"^\[Errno 2\] No such file or directory: '{re.escape(path)}'$"):
            cmd("dump_ca", self.ca.serial, path, stdout=BytesIO(), stderr=BytesIO())

        with self.assertCommandError(r"^Cannot dump bundle when using DER format\.$"):
            cmd(
                "dump_ca",
                self.ca.serial,
                format=Encoding.DER,
                bundle=True,
                stdout=BytesIO(),
                stderr=BytesIO(),
            )
