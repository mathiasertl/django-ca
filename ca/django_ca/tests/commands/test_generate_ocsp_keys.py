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

"""Test the generate_ocsp_keys management command."""

from unittest import mock

import pytest

from django_ca.celery.messages import UseCertificateAuthoritiesTaskArgs
from django_ca.models import CertificateAuthority
from django_ca.tests.base.assertions import assert_command_error
from django_ca.tests.base.constants import TIMESTAMPS
from django_ca.tests.base.utils import cmd
from django_ca.tests.commands.base import GenerateCommandTestCaseBase

# freeze time as otherwise CAs would not be valid
pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"]), pytest.mark.django_db]


class TestGenerateOcspKeys(GenerateCommandTestCaseBase):
    """Class collecting tests for this command."""

    cmd = "generate_ocsp_keys"
    single_path = "django_ca.management.commands.generate_ocsp_keys.Command.single_task"
    multiple_path = "django_ca.management.commands.generate_ocsp_keys.Command.multiple_task"

    def test_deprecated_command_name(self, multiple: mock.MagicMock) -> None:
        """Test the deprecated command-name alias."""
        stdout, stderr = cmd("regenerate_ocsp_keys")
        assert stdout == ""
        assert stderr == (
            "Warning: This command is deprecated. Please use generate_ocsp_keys instead. "
            "This alias will be removed in django_ca~=3.2.0.\n"
        )
        multiple.assert_called_once_with(UseCertificateAuthoritiesTaskArgs())


def test_model_validation_error(root: CertificateAuthority) -> None:
    """Test model validation is tested properly.

    NOTE: This example is contrived for the default backend, as the type of the password would already be
    checked by argparse. Other backends however might have other validation mechanisms.
    """
    with assert_command_error(r"^password: Input should be a valid string"):
        cmd("generate_ocsp_keys", root.serial, password=123)
