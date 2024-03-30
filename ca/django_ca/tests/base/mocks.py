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
