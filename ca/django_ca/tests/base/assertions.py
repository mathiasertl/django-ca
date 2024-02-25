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

""":py:mod:`django_ca.tests.base.assertions` collects assertions used throughout the entire test suite."""

import re
from contextlib import contextmanager
from typing import Iterator, Optional, Tuple, Union
from unittest.mock import Mock

import pytest

from django_ca.deprecation import RemovedInDjangoCA200Warning
from django_ca.signals import post_create_ca, pre_create_ca
from django_ca.tests.base.mocks import mock_signal


@contextmanager
def assert_create_ca_signals(pre: bool = True, post: bool = True) -> Iterator[Tuple[Mock, Mock]]:
    """Context manager asserting that the `pre_create_ca` and `post_create_ca` signals are (not) called."""
    with mock_signal(pre_create_ca) as pre_sig, mock_signal(post_create_ca) as post_sig:
        try:
            yield pre_sig, post_sig
        finally:
            assert pre_sig.called is pre
            assert post_sig.called is post


@contextmanager
def assert_removed_in_200(match: Optional[Union[str, "re.Pattern[str]"]] = None) -> Iterator[None]:
    """Assert that a ``RemovedInDjangoCA200Warning`` is emitted."""
    with pytest.warns(RemovedInDjangoCA200Warning, match=match):
        yield
