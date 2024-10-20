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

"""Test some code in the test base module to make sure it really works."""

import importlib
import io
import tempfile
import typing

from cryptography.x509.oid import ExtensionOID

from django.conf import settings
from django.test import TestCase

import pytest

from django_ca.tests.base.assertions import assert_extensions
from django_ca.tests.base.mixins import TestCaseMixin
from django_ca.tests.base.utils import cmd, cmd_e2e, override_tmpcadir
from django_ca.utils import add_colons


class TestDjangoCATestCase(TestCaseMixin, TestCase):
    """Test some basic stuff in the base test classes."""

    def test_pragmas(self) -> None:
        """Import the pragmas module to ensure coverage works correctly."""
        importlib.import_module("django_ca.tests.base.pragmas")

    @override_tmpcadir()
    def test_override_tmpcadir(self) -> None:
        """Test override_tmpcadir as decorator."""
        assert settings.CA_DIR.startswith(tempfile.gettempdir())

    @override_tmpcadir()
    def test_assert_extensions(self) -> None:
        """Test some basic extension properties."""
        self.load_named_cas("__usable__")
        self.load_named_certs("__usable__")

        assert_extensions(self.certs["no-extensions"], [], expect_defaults=False)
        assert_extensions(self.certs["no-extensions"].pub.loaded, [], expect_defaults=False)

        cert_key = "all-extensions"
        cert = self.certs[cert_key]
        assert_extensions(cert, cert.pub.loaded.extensions)

        # when we pass an x509 with a signer, we still have a default AuthorityKeyIdentifier extension
        assert_extensions(cert, cert.pub.loaded.extensions, signer=cert.ca)

        # now test root and child ca
        cert_key = "root"
        ca = self.cas[cert_key]

        root_extensions = [
            ca.extensions[ExtensionOID.BASIC_CONSTRAINTS],
            ca.extensions[ExtensionOID.KEY_USAGE],
        ]
        assert_extensions(ca, root_extensions)

        cert_key = "child"
        ca = self.cas[cert_key]

        root_extensions = [
            ca.extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS],
            ca.extensions[ExtensionOID.BASIC_CONSTRAINTS],
            ca.extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS],
            ca.extensions[ExtensionOID.KEY_USAGE],
        ]
        assert_extensions(ca, root_extensions)


class OverrideCaDirForFuncTestCase(TestCaseMixin, TestCase):
    """Test the override_tmpcadir decorator for a method.

    We do the same thing three times here, just to make sure that the result is really different.
    """

    # pylint: disable=missing-function-docstring

    seen_dirs: typing.ClassVar[set[str]] = set()

    @override_tmpcadir()
    def test_a(self) -> None:
        # add three tests to make sure that every test case sees a different dir
        assert settings.CA_DIR.startswith(tempfile.gettempdir())
        assert settings.CA_DIR not in self.seen_dirs
        self.seen_dirs.add(settings.CA_DIR)

    @override_tmpcadir()
    def test_b(self) -> None:
        assert settings.CA_DIR.startswith(tempfile.gettempdir())
        assert settings.CA_DIR not in self.seen_dirs
        self.seen_dirs.add(settings.CA_DIR)

    @override_tmpcadir()
    def test_c(self) -> None:
        assert settings.CA_DIR.startswith(tempfile.gettempdir())
        assert settings.CA_DIR not in self.seen_dirs
        self.seen_dirs.add(settings.CA_DIR)

    def test_no_classes(self) -> None:
        msg = r"^Only functions can use override_tmpcadir\(\)$"
        with pytest.raises(ValueError, match=msg):

            @override_tmpcadir()
            class Foo:  # pylint: disable=missing-class-docstring,unused-variable
                pass


class CommandTestCase(TestCaseMixin, TestCase):
    """Test the cmd_e2e function."""

    load_cas = ("root",)

    def test_basic(self) -> None:
        """Trivial basic test."""
        stdout, stderr = cmd_e2e(["list_cas"])
        serial = add_colons(self.ca.serial)
        assert stdout == f"{serial} - {self.ca.name}\n"
        assert stderr == ""


class TypingTestCase(TestCaseMixin):  # never executed as it's not actually a subclass of TestCase
    """Test case to create some code that would show an error in type checkers if type hinting is wrong.

    Note that none of these tests are designed to ever be executed.
    """

    # pylint: disable=missing-function-docstring

    def cmd_basic(self) -> tuple[str, str]:
        stdout, stderr = cmd("example")
        return stdout, stderr

    def cmd_explicit(self) -> tuple[str, str]:
        stdout, stderr = cmd("example", stdout=io.StringIO(), stderr=io.StringIO())
        return stdout, stderr

    def cmd_stdout_bytes(self) -> tuple[bytes, str]:
        stdout, stderr = cmd("example", stdout=io.BytesIO())
        return stdout, stderr

    def cmd_stderr_bytes(self) -> tuple[str, bytes]:
        stdout, stderr = cmd("example", stderr=io.BytesIO())
        return stdout, stderr

    def cmd_bytes(self) -> tuple[bytes, bytes]:
        stdout, stderr = cmd("example", stdout=io.BytesIO(), stderr=io.BytesIO())
        return stdout, stderr
