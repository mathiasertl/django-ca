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

"""Test basic views."""

from django.test import Client
from django.urls import reverse

from django_ca.models import CertificateAuthority


def test_generic_ca_issuers_view(usable_root: CertificateAuthority, client: Client) -> None:
    """Test the generic ca issuer view."""
    url = reverse("django_ca:issuer", kwargs={"serial": usable_root.serial})
    resp = client.get(url)
    assert resp["Content-Type"] == "application/pkix-cert"
    assert resp.content == usable_root.pub.der
