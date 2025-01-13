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

"""API utility functions."""

import typing
from typing import Any

from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from django.http import Http404

from django_ca.models import Certificate, CertificateAuthority

if typing.TYPE_CHECKING:
    from django.contrib.auth.models import User  # pylint: disable=imported-auth-user
else:
    from django.contrib.auth import get_user_model

    User = get_user_model()


def get_certificate_authority(serial: str, expired: bool = False) -> CertificateAuthority:
    """Get a certificate authority from the given serial."""
    qs = CertificateAuthority.objects.enabled().exclude(api_enabled=False)
    if expired is False:
        qs = qs.valid()

    try:
        return qs.get(serial=serial)
    except CertificateAuthority.DoesNotExist as ex:
        raise Http404(f"{serial}: Certificate authority not found.") from ex


@transaction.atomic
def create_api_user(
    username: str,
    password: str,
    view_certificateauthority: bool = True,
    change_certificateauthority: bool = True,
    sign_certificate: bool = True,
    view_certificate: bool = True,
    revoke_certificate: bool = True,
    **extra_fields: Any,
) -> User:
    """Create an API user capable of using the REST API.

    By default, the user will be able to perform all actions provided by the API.

    Note that *unlike* :py:meth:`~django:django.contrib.auth.models.UserManager.create_user`, the `password`
    argument is the second argument and mandatory. You can still pass an `email` address as keyword argument.

    >>> create_api_user("username", "password", revoke_certificate=False, email="user@example.com")
    <User: username>

    Parameters
    ----------
    username : str
        The username for the API user.
    password : str
        The password for the API user.
    view_certificateauthority : bool, optional
        If the user is able to list/view certificate authorities via the API.
    change_certificateauthority : bool, optional
        If the user is able to update certificate authorities via the API.
    sign_certificate : bool, optional
        If the user is able to sign new certificates via the API.
    view_certificate : bool, optional
        If the user is able to list/view existing certificates via the API.
    revoke_certificate : bool, optional
        If the user is able to revoke certificates via the API.
    **extra_fields
        Any additional keyword arguments are passed to
        :py:meth:`~django:django.contrib.auth.models.UserManager.create_user`.
    """
    ca_content_type = ContentType.objects.get_for_model(CertificateAuthority)
    cert_content_type = ContentType.objects.get_for_model(Certificate)

    user = User.objects.create_user(username, password=password, **extra_fields)

    permissions = []
    if view_certificateauthority is True:
        permissions.append(
            Permission.objects.get(codename="view_certificateauthority", content_type=ca_content_type)
        )
    if change_certificateauthority is True:
        permissions.append(
            Permission.objects.get(codename="change_certificateauthority", content_type=ca_content_type)
        )
    if sign_certificate is True:
        permissions.append(
            Permission.objects.get(codename="sign_certificate", content_type=cert_content_type)
        )
    if view_certificate is True:
        permissions.append(
            Permission.objects.get(codename="view_certificate", content_type=cert_content_type)
        )
    if revoke_certificate is True:
        permissions.append(
            Permission.objects.get(codename="revoke_certificate", content_type=cert_content_type)
        )
    user.user_permissions.add(*permissions)

    return user
