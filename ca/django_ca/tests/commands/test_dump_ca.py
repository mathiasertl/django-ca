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
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.serialization import Encoding

import pytest

from django_ca.models import CertificateAuthority
from django_ca.tests.base.assertions import assert_command_error
from django_ca.tests.base.utils import cmd


def dump_ca(serial: str, *args: Any, **kwargs: Any) -> bytes:
    """Execute the dump_ca command."""
    stdout, stderr = cmd("dump_ca", serial, *args, stdout=BytesIO(), stderr=BytesIO(), **kwargs)
    assert stderr == b"This command is deprecated. Use `view_ca --output-format {PEM,DER} instead.\n"
    return stdout


def test_basic(root: CertificateAuthority) -> None:
    """Basic test of this command."""
    stdout = dump_ca(root.serial)
    assert stdout.decode() == root.pub.pem


@pytest.mark.parametrize("encoding", (Encoding.PEM, Encoding.DER))
def test_format(root: CertificateAuthority, encoding: Encoding) -> None:
    """Test encoding parameter."""
    stdout = dump_ca(root.serial, format=encoding)
    assert stdout == root.pub.encode(encoding)


def test_explicit_stdout(root: CertificateAuthority) -> None:
    """Test piping to stdout."""
    stdout = dump_ca(root.serial, "-")
    assert stdout.decode() == root.pub.pem


def test_bundle(root: CertificateAuthority, child: CertificateAuthority) -> None:
    """Test getting the bundle."""
    stdout = dump_ca(root.serial, "-", bundle=True)
    assert stdout.decode() == root.pub.pem

    stdout = dump_ca(child.serial, "-", bundle=True)
    assert stdout.decode() == child.pub.pem + root.pub.pem


def test_file_output(tmp_path: Path, root: CertificateAuthority) -> None:
    """Test writing to file."""
    path = os.path.join(tmp_path, "test_ca.pem")
    stdout = dump_ca(root.serial, path)
    assert stdout == b""

    with open(path, encoding="ascii") as stream:
        assert stream.read() == root.pub.pem


def test_color_output_error(root: CertificateAuthority) -> None:
    """Test that requesting color output throws an error."""
    with assert_command_error("This command does not support color output."):
        dump_ca(root.serial, "/does/not/exist", force_color=True)


def test_errors(tmp_path: Path, root: CertificateAuthority) -> None:
    """Test some error conditions."""
    path = os.path.join(tmp_path, "does-not-exist", "test_ca.pem")
    with assert_command_error(rf"^\[Errno 2\] No such file or directory: '{re.escape(path)}'$"):
        dump_ca(root.serial, path)

    with assert_command_error(r"^Cannot dump bundle when using DER format\.$"):
        dump_ca(root.serial, format=Encoding.DER, bundle=True)
