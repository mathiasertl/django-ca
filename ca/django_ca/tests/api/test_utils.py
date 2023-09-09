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


"""Test utility functions."""
import doctest

import pytest

from django_ca.api import utils


@pytest.mark.django_db
def test_doctests() -> None:
    """Test doctests in the module."""
    failures, _tests = doctest.testmod(utils)
    assert failures == 0


@pytest.mark.django_db
def test_create_basic_user() -> None:
    """Test creating a minimal user."""
    user = utils.create_api_user("username", "foobar")
    assert user.username == "username"
    assert user.check_password("foobar") is True
    assert user.has_perm("django_ca.view_certificateauthority") is True
    assert user.has_perm("django_ca.change_certificateauthority") is True
    assert user.has_perm("django_ca.view_certificate") is True
    assert user.has_perm("django_ca.sign_certificate") is True
    assert user.has_perm("django_ca.revoke_certificate") is True


@pytest.mark.django_db
def test_additional_properties() -> None:
    """Test passing additional properties."""
    user = utils.create_api_user("username", "foobar", email="user@example.com")
    assert user.username == "username"
    assert user.check_password("foobar") is True
    assert user.email == "user@example.com"


@pytest.mark.django_db
def test_no_permissions() -> None:
    """Create a user, but rule out all permissions."""
    user = utils.create_api_user(
        "username",
        "foobar",
        view_certificateauthority=False,
        change_certificateauthority=False,
        sign_certificate=False,
        view_certificate=False,
        revoke_certificate=False,
    )
    assert user.username == "username"
    assert user.check_password("foobar") is True

    assert user.has_perm("django_ca.view_certificateauthority") is False
    assert user.has_perm("django_ca.change_certificateauthority") is False
    assert user.has_perm("django_ca.view_certificate") is False
    assert user.has_perm("django_ca.sign_certificate") is False
    assert user.has_perm("django_ca.revoke_certificate") is False
