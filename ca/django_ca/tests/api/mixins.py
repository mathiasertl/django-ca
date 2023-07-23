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

"""TestCase mixins for API view tests."""
import base64
import typing
from datetime import datetime
from http import HTTPStatus
from typing import Any, Tuple, Type

from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db.models import Model

from django_ca.tests.base.mixins import TestCaseMixin

if typing.TYPE_CHECKING:
    from django.contrib.auth.models import User  # pylint: disable=imported-auth-user  # required by mypy
    from django.test.client import _MonkeyPatchedWSGIResponse as HttpResponse
else:
    from django.contrib.auth import get_user_model

    User = get_user_model()


class APITestCaseMixin(TestCaseMixin):
    """TestCase mixin for API view tests."""

    path: str
    required_permission: Tuple[Type[Model], str]
    method = "get"
    default_ca = "root"
    load_cas = ("root",)

    def setUp(self) -> None:
        super().setUp()
        self.user = self.create_api_user()

        # Set up credentials for the client
        credentials = base64.b64encode(b"api:password").decode()
        self.client.defaults["HTTP_AUTHORIZATION"] = "Basic " + credentials

        # give the user the required permission
        content_type = ContentType.objects.get_for_model(self.required_permission[0])
        permission = Permission.objects.get(codename=self.required_permission[1], content_type=content_type)
        self.user.user_permissions.add(permission)

    def create_api_user(self, username: str = "api", password: str = "password") -> "User":
        """Shortcut to create an API user."""
        return User.objects.create_user(username=username, password=password)

    def iso_format(self, value: datetime, timespec: str = "seconds") -> str:
        """Convert a timestamp to ISO, with 'Z' instead of '+00:00'."""
        return value.isoformat(timespec=timespec).replace("+00:00", "Z")

    def default_request(self, *args: Any, **kwargs: Any) -> "HttpResponse":
        """Make a default request to the view under test.

        GET views can use the default implementation, all other HTTP verbs will have to override this.
        """
        return self.client.get(self.path, *args, **kwargs)

    def test_request_with_no_authentication(self) -> None:
        """Test that a request with no authorization returns an HTTP 403 Unauthorized response."""
        del self.client.defaults["HTTP_AUTHORIZATION"]
        response = self.default_request()
        self.assertEqual(response.status_code, HTTPStatus.UNAUTHORIZED, response.json())
        self.assertEqual(response.json(), {"detail": "Unauthorized"})

    def test_user_with_wrong_password(self) -> None:
        """Test that a user with the wrong password gets an HTTP 403 Unauthorized response."""
        credentials = base64.b64encode(b"api:wrong-password").decode()
        self.client.defaults["HTTP_AUTHORIZATION"] = "Basic " + credentials

        response = self.default_request()
        self.assertEqual(response.status_code, HTTPStatus.UNAUTHORIZED, response.json())
        self.assertEqual(response.json(), {"detail": "Unauthorized"})

    def test_user_with_no_permissions(self) -> None:
        """Test that a user without the required permissions gets an HTTP 401 Forbidden response."""
        self.user.user_permissions.clear()
        response = self.default_request()
        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN, response.json())
        self.assertEqual(response.json(), {"detail": "Forbidden"})
