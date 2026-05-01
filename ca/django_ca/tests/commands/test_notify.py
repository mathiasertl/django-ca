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

"""Test the notify_expiring_certs management command."""

from unittest import mock

import pytest

from django_ca.tasks import notify_watchers
from django_ca.tests.base.utils import cmd

pytestmark = [pytest.mark.django_db]


def test_calls_task() -> None:
    """The command delegates to the notify_watchers task via run_task."""
    with mock.patch("django_ca.management.commands.notify_expiring_certs.run_task") as mock_run_task:
        stdout, stderr = cmd("notify_expiring_certs")
    assert stdout == ""
    assert stderr == ""
    mock_run_task.assert_called_once_with(notify_watchers)


def test_deprecated_days_option() -> None:
    """Passing --days prints a deprecation warning to stdout."""
    with mock.patch("django_ca.management.commands.notify_expiring_certs.run_task") as mock_run_task:
        stdout, stderr = cmd("notify_expiring_certs", days=3)
    warning = "The --days option no longer has any effect and will be removed in django-ca==3.3.0."
    assert stdout == f"{warning}\n"
    assert stderr == ""
    mock_run_task.assert_called_once_with(notify_watchers)
