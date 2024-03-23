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

"""Test the cert_watchers management command."""

from django_ca.models import Certificate
from django_ca.tests.base.utils import cmd


def test_basic(root_cert: Certificate) -> None:
    """Just some basic tests here."""
    stdout, stderr = cmd("cert_watchers", root_cert.serial, add=["user-added@example.com"])
    assert stdout == ""
    assert stderr == ""
    assert root_cert.watchers.filter(mail="user-added@example.com").exists() is True

    # remove user again
    stdout, stderr = cmd("cert_watchers", root_cert.serial, rm=["user-added@example.com"])
    assert stdout == ""
    assert stderr == ""
    assert root_cert.watchers.filter(mail="user-added@example.com").exists() is False

    # removing again does nothing, but doesn't throw an error either
    stdout, stderr = cmd("cert_watchers", root_cert.serial, rm=["user-added@example.com"])
    assert stdout == ""
    assert stderr == ""
    assert root_cert.watchers.filter(mail="user-added@example.com").exists() is False
