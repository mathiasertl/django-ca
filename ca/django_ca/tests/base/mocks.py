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

"""Mocks used in the test suite."""

import json
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from unittest import mock

from django.db import models
from django.dispatch.dispatcher import Signal


@contextmanager
def mock_signal(signal: Signal) -> Iterator[mock.Mock]:
    """Context manager to attach a mock to the given Django signal.

    Note that this mock does not mock that the signal is sent, but just attaches a mock to the Signal. Any
    other signal handler connected would still be called.
    """

    # This function is only here to create an autospec. From the documentation:
    #
    #   Notice that the function takes a sender argument, along with wildcard keyword arguments
    #   (**kwargs); all signal handlers must take these arguments.
    #
    # https://docs.djangoproject.com/en/dev/topics/signals/#connecting-to-specific-signals
    def callback(sender: models.Model, **kwargs: Any) -> None:  # pragma: no cover
        # pylint: disable=unused-argument
        pass

    signal_mock = mock.create_autospec(callback, spec_set=True)
    signal.connect(signal_mock)
    try:
        yield signal_mock
    finally:
        signal.disconnect(signal_mock)


@contextmanager
def mock_celery_task(task: str, *calls: tuple[tuple[Any, ...], dict[str, Any]]) -> Iterator[mock.MagicMock]:
    """Context manager to mock celery invocations.

    This context manager mocks ``celery.app.task.Task.apply_async``, the final function in celery before
    the message is passed to the handlers for the configured message transport (Redis, MQTT, ...). The
    context manager will validate the mock was called as specified in `calls`.

    The context manager will also assert that the `args` and `kwargs` passed to the tasks are JSON
    serializable.

    .. WARNING::

       The `args` and `kwargs` passed to the task are the first and second *argument* passed to the mocked
       ``apply_async``. You must consider this when passing calls. For example::

           with self.mock_celery_task("django_ca.tasks.cache_crls", (((), {}), {})):
               cache_crls.delay()

           with self.mock_celery_task("django_ca.tasks.cache_crls", ((("foo"), {"key": "bar"}), {})):
               cache_crls.delay("foo", key="bar")
    """
    with mock.patch(f"{task}.apply_async", spec_set=True) as mocked:
        yield mocked

    # Make sure that all invocations are JSON serializable
    for invocation in mocked.call_args_list:
        # invocation apply_async() has task args as arg[0] and arg[1]
        assert isinstance(json.dumps(invocation.args[0]), str)
        assert isinstance(json.dumps(invocation.args[1]), str)

    # Make sure that task was called the right number of times
    assert len(calls) == len(mocked.call_args_list), (len(calls), len(mocked.call_args_list), calls)
    for expected, actual in zip(calls, mocked.call_args_list, strict=False):
        print("exp", expected)
        print("act", actual)
        assert expected == actual, (expected, actual)
