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

"""Test :py:class:`django_ca.querysets.CertificateAuthorityQuerySet`."""

import pytest

from django_ca.models import CertificateAuthority
from django_ca.querysets import CertificateAuthorityQuerySet
from django_ca.tests.querysets.conftest import X509CertMixinQuerySetTestCaseBase


class TestX509CertMixin(
    X509CertMixinQuerySetTestCaseBase[CertificateAuthority, CertificateAuthorityQuerySet]
):
    """Tests for methods defined in X509CertMixinQuerySet."""

    model = CertificateAuthority

    @pytest.fixture
    def obj(self, request: pytest.FixtureRequest, root: CertificateAuthority) -> CertificateAuthority:
        """Overwritten to honor requires_ca fixture."""
        marker = request.node.get_closest_marker("requires_ca")
        if marker is None:
            return root
        obj = request.getfixturevalue(marker.args[0])
        assert isinstance(obj, CertificateAuthority)
        return obj


def test_enabled(root: CertificateAuthority) -> None:
    """Test enabled()."""
    assert root.enabled is True
    assert list(CertificateAuthority.objects.all().enabled()) == [root]

    root.enabled = False
    root.save()

    assert not list(CertificateAuthority.objects.all().enabled())


def test_acme_enabled(root: CertificateAuthority) -> None:
    """Test acme_enabled()."""
    assert root.acme_enabled is True
    assert list(CertificateAuthority.objects.all().acme()) == [root]

    root.acme_enabled = False
    root.save()

    assert not list(CertificateAuthority.objects.all().acme())
