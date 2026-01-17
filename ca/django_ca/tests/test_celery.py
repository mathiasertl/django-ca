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

"""Tests for django_ca.celery."""

from unittest import mock

import pytest
from pytest_django.fixtures import SettingsWrapper

from django_ca import tasks
from django_ca.celery import DjangoCaTask, run_task, shared_task
from django_ca.celery.base import CeleryMessageModel, dummy_shared_task
from django_ca.tests.base.mocks import mock_celery_task


class CeleryMessage(CeleryMessageModel):
    """Message used in tests."""

    value: int
    optional: int = 0


@dummy_shared_task
def _dummy_task(arg: int = 0) -> int:
    return arg


@dummy_shared_task()
def _dummy_task_with_braces(arg: int = 1) -> int:
    return arg


@dummy_shared_task(foo=True)  # arguments to the decorator are ignored
def _dummy_task_with_args(arg: int = 2) -> int:
    return arg


@shared_task(base=DjangoCaTask)
def no_arg_task() -> int:
    """Task with no arguments that does nothing."""
    return 1


@shared_task(base=DjangoCaTask)
def arg_task(data: CeleryMessage) -> CeleryMessage:
    """Task with a data argument."""
    assert isinstance(data, CeleryMessage)
    return CeleryMessage(value=data.value + 1, optional=data.optional + 1)


@shared_task(base=DjangoCaTask)
def optional_arg_task(data: CeleryMessage | None = None) -> CeleryMessage | None:
    """Task with an optional argument."""
    return data  # only tested via call()


def test_no_arg_task_delay() -> None:
    """Call a task that takes no arguments via delay()."""
    with mock_celery_task("django_ca.tests.test_celery.no_arg_task", mock.call(tuple(), {})):
        no_arg_task.delay()


def test_no_arg_task_call() -> None:
    """Directly call a task that takes no arguments."""
    assert no_arg_task() == 1


def test_no_arg_task_call_with_argument() -> None:
    """Directly call a task that takes no arguments, but with an argument."""
    with pytest.raises(TypeError, match=r"data received but task does not define a `data` argument\."):
        no_arg_task(1)  # type: ignore[call-arg]  # what we're testing

    with pytest.raises(TypeError, match=r"data received but task does not define a `data` argument\."):
        no_arg_task(CeleryMessage(value=1))  # type: ignore[call-arg]  # what we're testing


def test_arg_task_delay() -> None:
    """Call a task that takes an arguments via delay()."""
    msg = CeleryMessage(value=1)
    with mock_celery_task("django_ca.tests.test_celery.arg_task", mock.call(tuple(), {"data": {"value": 1}})):
        arg_task.delay(msg)

    msg = CeleryMessage(value=1, optional=3)
    with mock_celery_task(
        "django_ca.tests.test_celery.arg_task", mock.call(tuple(), {"data": {"value": 1, "optional": 3}})
    ):
        arg_task.delay(msg)


def test_arg_task_call() -> None:
    """Directly call a task that takes an argument."""
    assert arg_task(CeleryMessage(value=1)) == CeleryMessage(value=2, optional=1)


def test_arg_task_call_with_no_argument() -> None:
    """Directly call a task that takes an argument."""
    with pytest.raises(TypeError, match=r"No data received but `data` argument is not optional\."):
        arg_task()  # type: ignore[misc,call-arg]  # what we're testing


def test_arg_task_delay_with_invalid_type() -> None:
    """Call a task that takes an arguments via delay(), but passing an invalid type."""
    with pytest.raises(TypeError, match=r"Not a model instance\."):
        arg_task.delay({"data": {"value": 1}})  # type: ignore[arg-type]  # what we're testing


def test_arg_task_with_wrong_typehint() -> None:
    """Test a task that has a data argument, but it's not a celery message."""

    @shared_task(base=DjangoCaTask)
    def arg_task_with_wrong_typehint(data: int) -> int:
        return data

    with pytest.raises(TypeError, match=r"Not a subclass of CeleryMessageModel\."):
        arg_task_with_wrong_typehint(1)


def test_arg_task_with_wrong_arguments() -> None:
    """Test a task that has a data argument, but it's not a celery message."""

    @shared_task(base=DjangoCaTask)
    def arg_task_with_wrong_arguments(data: CeleryMessage, extra: int = 1) -> int:
        return data.value + extra

    with pytest.raises(
        TypeError, match=r"Task does not define a `data` argument or defines extra arguments\."
    ):
        arg_task_with_wrong_arguments(1)  # type: ignore[arg-type]  # what we're testing


def test_optional_arg_task_delay() -> None:
    """Call a task that takes an optional arguments via delay()."""
    assert optional_arg_task() is None

    msg = CeleryMessage(value=1)
    assert optional_arg_task(msg) == msg


def test_dummy_task() -> None:
    """Test dummy task decorator."""
    assert _dummy_task() == 0
    assert _dummy_task.delay() == 0  # type: ignore[comparison-overlap]
    assert _dummy_task(1) == 1
    assert _dummy_task.delay(1) == 1  # type: ignore[comparison-overlap]


def test_dummy_task_with_braces() -> None:
    """Test dummy task decorator when called with braces."""
    assert _dummy_task_with_braces() == 1
    assert _dummy_task_with_braces.delay() == 1  # type: ignore[comparison-overlap]
    assert _dummy_task_with_braces(3) == 3
    assert _dummy_task_with_braces.delay(3) == 3  # type: ignore[comparison-overlap]


def test_dummy_task_with_args() -> None:
    """Test dummy task decorator when called with arguments."""
    assert _dummy_task_with_args() == 2
    assert _dummy_task_with_args.delay() == 2  # type: ignore[comparison-overlap]
    assert _dummy_task_with_args(3) == 3
    assert _dummy_task_with_args.delay(3) == 3  # type: ignore[comparison-overlap]


def test_run_task(settings: SettingsWrapper) -> None:
    """Test our run_task wrapper."""
    # run_task() without celery
    settings.CA_USE_CELERY = False
    with mock.patch("django_ca.tasks.generate_crls") as task_mock:
        run_task(tasks.generate_crls)
    assert task_mock.call_count == 1
