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

"""Authentication classes for the API."""

from typing import Literal, Union

from ninja.security import HttpBasicAuth

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractUser
from django.http import HttpRequest

from django_ca.api.errors import Forbidden

User = get_user_model()


class BasicAuth(HttpBasicAuth):
    """HTTP Basic Authentication and permission checking.

    The class will raise :py:class:`~django_ca.api.errors.Forbidden` if the user lacks sufficient permissions.

    Parameters
    ----------
    permission : str
        The permission that the user needs to have in order to pass authn/authz checks.
    """

    def __init__(self, permission: str) -> None:
        self.permission = permission
        super().__init__()

    def authenticate(
        self, request: HttpRequest, username: str, password: str
    ) -> Union[Literal[False], AbstractUser]:
        user = User.objects.get(username=username)
        if user.check_password(password) is False:
            return False
        if user.has_perm(self.permission) is False:
            raise Forbidden(self.permission)
        return user
