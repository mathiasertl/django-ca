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

    media_css = []
    """List of custom CSS files loaded by the ModelAdmin.Media class."""

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

        for css in self.media_css:
            self.assertCSS(response, css)

    def assertChangelistResponse(self, response, *objects,  # pylint: disable=invalid-name
                                 status=HTTPStatus.OK):
        """Assert that the passed response is a model changelist view."""
        self.assertEqual(response.status_code, status)
        self.assertCountEqual(response.context['cl'].result_list, objects)

        templates = [t.name for t in response.templates]
        self.assertIn('admin/base.html', templates)
        self.assertIn('admin/change_list.html', templates)

        for css in self.media_css:
            self.assertCSS(response, css)

    def assertRequiresLogin(self, response, **kwargs):  # pylint: disable=invalid-name
        """Assert that the given response is a redirect to the login page."""
        expected = '%s?next=%s' % (reverse('admin:login'), quote(response.wsgi_request.get_full_path()))
        self.assertRedirects(response, expected, **kwargs)

    @classmethod
    def change_url(cls, obj):
        """Shortcut for the change URL of the given instance."""
        return obj.admin_change_url

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

    def get_changelist_view(self, data=None):
        """Get the response to a changelist view for the given model."""
        return self.client.get(self.changelist_url, data)

    def get_change_view(self, obj, data=None):
        """Get the response to a change view for the given model instance."""
        return self.client.get(self.change_url(obj), data)


class StandardAdminViewTestCaseMixin(AdminTestCaseMixin):
    """A mixin that adds tests for the standard Django admin views.

    TestCases using this mixin are expected to implement ``setUp`` to add some useful test model instances.
    """

    def get_changelists(self):
        """Generator for possible changelist views.

        Should yield tuples of objects that should be displayed and a dict of query parameters.
        """
        yield (self.model.objects.all(), {})

    def test_model_count(self):
        """Test that the implementing TestCase actually creates some instances."""
        self.assertGreater(self.model.objects.all().count(), 0)

    def test_changelist_view(self):
        """Test that the changelist view works."""
        for qs, data in self.get_changelists():
            self.assertChangelistResponse(self.get_changelist_view(data), *qs)

    def test_change_view(self):
        """Test that the change view works for all instances."""
        for obj in self.model.objects.all():
            self.assertChangeResponse(self.get_change_view(obj))
