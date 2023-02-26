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

"""Mixin classes for admin view test cases."""

import typing

from django_ca.models import Certificate
from django_ca.tests.base.mixins import AdminTestCaseMixin


class CertificateAdminTestCaseMixin:
    """Mixin that defines the ``media_css`` property for certificates.

    This does **not** set the ``model`` property, as mypy then complains about incompatible types in base
    classes.
    """

    media_css: typing.Tuple[str, ...] = (
        "django_ca/admin/css/base.css",
        "django_ca/admin/css/certificateadmin.css",
    )


class CertificateModelAdminTestCaseMixin(CertificateAdminTestCaseMixin, AdminTestCaseMixin[Certificate]):
    """Specialized variant of :py:class:`~django_ca.tests.tests_admin.AdminTestCaseMixin` for certificates."""

    model = Certificate
