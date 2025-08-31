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

"""Test the dump_cert management command."""

import re
from io import BytesIO
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.serialization import Encoding

import pytest

from django_ca.models import Certificate
from django_ca.tests.base.assertions import assert_command_error
from django_ca.tests.base.utils import cmd

pytestmark = pytest.mark.django_db


def dump_cert(serial: str, *args: Any, **kwargs: Any) -> bytes:
    """Execute the dump_cert command."""
    stdout, stderr = cmd("dump_cert", serial, *args, stdout=BytesIO(), stderr=BytesIO(), **kwargs)
    assert stderr == b"This command is deprecated. Use `view_cert --output-format {PEM,DER} instead.\n"
    return stdout


def test_basic(root_cert: Certificate) -> None:
    """Basic test of this command."""
    stdout = dump_cert(root_cert.serial)
    assert stdout.decode() == root_cert.pub.pem


@pytest.mark.parametrize("encoding", (Encoding.PEM, Encoding.DER))
def test_format(root_cert: Certificate, encoding: Encoding) -> None:
    """Test encoding formats."""
    stdout = dump_cert(root_cert.serial, format=encoding)
    assert stdout == root_cert.pub.encode(encoding)


def test_explicit_stdout(root_cert: Certificate) -> None:
    """Test writing to stdout."""
    stdout = dump_cert(root_cert.serial, "-")
    assert stdout.decode() == root_cert.pub.pem


def test_bundle(root_cert: Certificate) -> None:
    """Test getting the bundle."""
    stdout = dump_cert(root_cert.serial, bundle=True)
    assert stdout.decode() == root_cert.pub.pem + root_cert.ca.pub.pem


def test_file_output(tmp_path: Path, root_cert: Certificate) -> None:
    """Test writing to a file."""
    destination = tmp_path / "cert.pem"
    stdout = dump_cert(root_cert.serial, destination)
    assert stdout == b""

    with open(destination, encoding="ascii") as stream:
        assert stream.read() == root_cert.pub.pem


def test_directory_does_not_exist(tmp_path: Path, root_cert: Certificate) -> None:
    """Test writing to a directory that does not exist."""
    destination = tmp_path / "does-not-exist" / "cert.pem"
    msg = rf"^\[Errno 2\] No such file or directory: '{re.escape(str(destination))}'$"
    with assert_command_error(msg):
        dump_cert(root_cert.serial, destination)


def test_der_bundle_error(root_cert: Certificate) -> None:
    """Test writing a DER bundle (which does not work)."""
    with assert_command_error(r"^Cannot dump bundle when using DER format\.$"):
        dump_cert(root_cert.serial, format=Encoding.DER, bundle=True)
