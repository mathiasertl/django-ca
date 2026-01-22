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

"""Base class for various test cases."""

from collections.abc import Iterator
from typing import ClassVar
from unittest import mock

import pytest

from django_ca.celery.messages import UseCertificateAuthoritiesTaskArgs, UseCertificateAuthorityTaskArgs
from django_ca.models import CertificateAuthority
from django_ca.tests.base.assertions import assert_command_error
from django_ca.tests.base.utils import cmd


class GenerateCommandTestCaseBase:
    """Base class for generate_* commands."""

    cmd: ClassVar[str]
    single_path: ClassVar[str]
    multiple_path: ClassVar[str]

    @pytest.fixture
    def single(self) -> Iterator[mock.MagicMock]:
        """Fixture for mocking the single CA task."""
        with mock.patch(self.single_path, autospec=True) as task_mock:
            yield task_mock

    @pytest.fixture
    def multiple(self) -> Iterator[mock.MagicMock]:
        """Fixture for mocking the multiple CA task."""
        with mock.patch(self.multiple_path, autospec=True) as task_mock:
            yield task_mock

    def test_with_no_args(self, multiple: mock.MagicMock) -> None:
        """Invoke with no arguments."""
        stdout, stderr = cmd(self.cmd)
        assert stdout == ""
        assert stderr == ""
        multiple.assert_called_once_with(UseCertificateAuthoritiesTaskArgs())

    def test_with_serial(self, single: mock.MagicMock, root: CertificateAuthority) -> None:
        """Invoke with serial."""
        stdout, stderr = cmd(self.cmd, root.serial)
        assert stdout == ""
        assert stderr == ""
        single.assert_called_once_with(UseCertificateAuthorityTaskArgs(serial=root.serial))

    def test_with_exclude(self, multiple: mock.MagicMock, root: CertificateAuthority) -> None:
        """Test passing an explicit serial."""
        cmd(self.cmd, exclude=[root.serial])
        multiple.assert_called_once_with(UseCertificateAuthoritiesTaskArgs(exclude=[root.serial]))

    @pytest.mark.usefixtures("root")
    def test_with_force(self, multiple: mock.MagicMock) -> None:
        """Test passing an explicit serial."""
        cmd(self.cmd, force=True)
        multiple.assert_called_once_with(UseCertificateAuthoritiesTaskArgs(force=True))

    def test_unknown_serial(self) -> None:
        """Try passing an invalid CA."""
        with assert_command_error(r"^0A:BC: Unknown CA\.$"):
            cmd(self.cmd, "abc")

    def test_invalid_serial(self) -> None:
        """Try passing an invalid CA."""
        with assert_command_error(r"^ZZZZZ: Serial has invalid characters$"):
            cmd(self.cmd, "ZZZZZ")

    def test_with_serial_and_exclude(self) -> None:
        """Test passing both an explicit serial and an exclusion (makes no sense)."""
        with assert_command_error(r"^Cannot name serials and exclude list at the same time\.$"):
            cmd(self.cmd, ["abc"], exclude=["def"])
