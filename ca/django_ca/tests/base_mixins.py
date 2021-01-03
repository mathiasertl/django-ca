# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca.  If not,
# see <http://www.gnu.org/licenses/>

"""Collection of mixin classes for unittest.TestCase subclasses."""

from contextlib import contextmanager
from http import HTTPStatus
from urllib.parse import quote

from django.templatetags.static import static
from django.urls import reverse

from ..utils import classproperty


class AdminTestCaseMixin:
    """Common mixin for testing admin classes for models."""

    model = None
    """Model must be configured for TestCase instances using this mixin."""

    def setUp(self):  # pylint: disable=invalid-name,missing-function-docstring
        self.user = self.create_superuser()
        self.client.force_login(self.user)
        super().setUp()

    @classproperty
    def add_url(cls):  # pylint: disable=no-self-argument; pylint does not detect django decorator
        """Shortcut for the "add" URL of the model under test."""
        return cls.model.admin_add_url

    def assertCSS(self, response, path):  # pylint: disable=invalid-name
        """Assert that the HTML from the given response includes the mentioned CSS."""
        css = '<link href="%s" type="text/css" media="all" rel="stylesheet" />' % static(path)
        self.assertInHTML(css, response.content.decode('utf-8'), 1)

    def assertChangeResponse(self,  # pylint: disable=invalid-name
                             response, status=HTTPStatus.OK):
        """Assert that the passed response is a model change view."""
        self.assertEqual(response.status_code, status)
        templates = [t.name for t in response.templates]
        self.assertIn('admin/change_form.html', templates)
        self.assertIn('admin/base.html', templates)

    def assertChangelistResponse(self, response, *objects,  # pylint: disable=invalid-name
                                 status=HTTPStatus.OK):
        """Assert that the passed response is a model changelist view."""
        self.assertEqual(response.status_code, status)
        self.assertCountEqual(response.context['cl'].result_list, objects)

        templates = [t.name for t in response.templates]
        self.assertIn('admin/base.html', templates)
        self.assertIn('admin/change_list.html', templates)

    def assertRequiresLogin(self, response, **kwargs):  # pylint: disable=invalid-name
        """Assert that the given response is a redirect to the login page."""
        expected = '%s?next=%s' % (reverse('admin:login'), quote(response.wsgi_request.get_full_path()))
        self.assertRedirects(response, expected, **kwargs)

    @classproperty
    def changelist_url(cls):  # pylint: disable=no-self-argument; pylint does not detect django decorator
        """Shortcut for the changelist URL of the model under test."""
        return cls.model.admin_changelist_url

    @contextmanager
    def freeze_time(self, timestamp):
        """Overridden to force a client login, otherwise the user session is expired."""

        with super().freeze_time(timestamp) as frozen:
            self.client.force_login(self.user)
            yield frozen
