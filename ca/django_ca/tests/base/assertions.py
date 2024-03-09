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
from http import HTTPStatus
from typing import Any, Iterator, Optional, Tuple, Union
from unittest.mock import Mock

from django.db import models
from django.templatetags.static import static

import pytest
from pytest_django.asserts import assertInHTML

from django_ca.deprecation import RemovedInDjangoCA200Warning
from django_ca.signals import post_create_ca, pre_create_ca
from django_ca.tests.base.mocks import mock_signal
from django_ca.tests.base.typehints import HttpResponse


def assert_change_response(
    response: "HttpResponse", media_css: Tuple[Tuple[str, str], ...] = tuple()
) -> None:
    """Assert that the passed response is a model change view."""
    assert response.status_code == HTTPStatus.OK, f"HTTP {response.status_code}"
    templates = [t.name for t in response.templates]
    assert "admin/change_form.html" in templates
    assert "admin/base.html" in templates

    for url_path, media in media_css:
        assert_css(response, url_path, media)


def assert_changelist_response(response: "HttpResponse", *objects: models.Model) -> None:
    """Assert that the passed response is a model changelist view."""
    assert response.status_code == HTTPStatus.OK, f"HTTP {response.status_code}"

    def sorter(obj: models.Model) -> Any:
        return obj.pk

    assert sorted(response.context["cl"].result_list, key=sorter) == sorted(objects, key=sorter)
    templates = [t.name for t in response.templates]
    assert "admin/base.html" in templates
    assert "admin/change_list.html" in templates


@contextmanager
def assert_create_ca_signals(pre: bool = True, post: bool = True) -> Iterator[Tuple[Mock, Mock]]:
    """Context manager mocking both pre and post_create_ca signals."""
    with mock_signal(pre_create_ca) as pre_sig, mock_signal(post_create_ca) as post_sig:
        try:
            yield pre_sig, post_sig
        finally:
            assert pre_sig.called is pre
            assert post_sig.called is post


def assert_css(response: "HttpResponse", path: str, media: str = "all") -> None:
    """Assert that the HTML from the given response includes the mentioned CSS."""
    css = f'<link href="{static(path)}" media="{media}" rel="stylesheet" />'
    assertInHTML(css, response.content.decode("utf-8"), 1)


@contextmanager
def assert_removed_in_200(match: Optional[Union[str, "re.Pattern[str]"]] = None) -> Iterator[None]:
    """Assert that a RemovedInDjangoCA200Warning is emitted."""
    with pytest.warns(RemovedInDjangoCA200Warning, match=match):
        yield
