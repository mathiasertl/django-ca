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

"""Test :py:class:`django_ca.querysets.CertificateQuerySet`."""

import pytest

from django_ca.models import Certificate
from django_ca.querysets import CertificateQuerySet
from django_ca.tests.querysets.conftest import X509CertMixinQuerySetTestCaseBase


class TestX509CertMixin(X509CertMixinQuerySetTestCaseBase[Certificate, CertificateQuerySet]):
    """Tests for methods defined in X509CertMixinQuerySet."""

    model = Certificate

    @pytest.fixture
    def obj(self, root_cert: Certificate) -> Certificate:
        """Fixture is an alias for `root_cert`."""
        return root_cert
