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

"""Test generate_ocsp_responses command."""

from unittest import mock

from pytest_django.fixtures import SettingsWrapper

from django_ca.tests.base.mocks import mock_celery_task
from django_ca.tests.base.utils import cmd


def test_command(settings: SettingsWrapper) -> None:
    """Test running the command."""
    settings.CA_USE_CELERY = False
    with mock.patch(
        "django_ca.management.commands.generate_ocsp_responses.generate_ocsp_responses", autospec=True
    ) as task_mock:
        cmd("generate_ocsp_responses")
    task_mock.assert_called_once_with()


def test_command_with_celery(settings: SettingsWrapper) -> None:
    """Test running the command with Celery enabled."""
    settings.CA_USE_CELERY = True
    with mock_celery_task("django_ca.tasks.generate_ocsp_responses", mock.call((), {})):
        cmd("generate_ocsp_responses")
