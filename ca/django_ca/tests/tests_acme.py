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
# see <http://www.gnu.org/licenses/>.

"""Test some common ACME functionality."""

from contextlib import contextmanager
from importlib import reload

import acme

from django.urls import include
from django.urls import path
from django.urls import reverse
from django.urls.exceptions import NoReverseMatch

from .. import urls
from ..acme.constants import IdentifierType
from ..acme.constants import Status
from .base import DjangoCATestCase
from .base import override_settings

urlpatterns = [
    path('django_ca/', include('django_ca.urls')),
]


class URLPatternTestCase(DjangoCATestCase):
    """Test that URL patterns are not enabled when CA_ENABLE_ACME."""

    @contextmanager
    def reload_urlconf(self):
        """Context manager to reload the current URL configuration."""
        reload(urls)
        try:
            with self.settings(ROOT_URLCONF=__name__):
                yield
        finally:
            reload(urls)

    @contextmanager
    def assertNoReverseMatch(self, name, args=None, kwargs=None):  # pylint: disable=invalid-name
        """Context manager asserting that the given URL pattern is **not** found."""
        urlname = name
        if ':' in name:
            _namespace, urlname = name.split(':', 1)

        msg = f"Reverse for '{urlname}' not found. '{urlname}' is not a valid view function or pattern name."
        with self.assertRaisesRegex(NoReverseMatch, msg):
            reverse(name, args, kwargs)

    @override_settings(CA_ENABLE_ACME=False)
    def test_disabled(self):
        """Test that resolving URLs does **NOT** work if disabled."""
        with self.reload_urlconf():
            self.assertNoReverseMatch('django_ca:acme-directory')
            self.assertNoReverseMatch('django_ca:acme-directory', kwargs={'serial': 'AB:CD'})
            self.assertNoReverseMatch('django_ca:acme-new-nonce', kwargs={'serial': 'AB:CD'})

    def test_enabled(self):
        """Test that resolving URLs work if enabled."""

        reverse('django_ca:acme-directory')
        reverse('django_ca:acme-directory', kwargs={'serial': 'AB:CD'})
        reverse('django_ca:acme-new-nonce', kwargs={'serial': 'AB:CD'})


class TestConstantsTestCase(DjangoCATestCase):
    """Test constants."""

    def test_status_enum(self):
        """Test that the Status Enum is equivalent to the main ACME library."""

        expected = list(acme.messages.Status.POSSIBLE_NAMES) + ['expired']
        self.assertCountEqual(expected,
                              [s.value for s in Status])

    def test_identifier_enum(self):
        """Test that the IdentifierType Enum is equivalent to the main ACME library."""

        self.assertCountEqual(acme.messages.IdentifierType.POSSIBLE_NAMES,
                              [s.value for s in IdentifierType])
