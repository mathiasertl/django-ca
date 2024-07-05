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

"""Common functions for testing models."""

from django_ca.models import X509CertMixin
from django_ca.tests.base.constants import CERT_PEM_REGEX


def assert_bundle(chain: list[X509CertMixin], cert: X509CertMixin) -> None:
    """Assert that a bundle contains the expected certificates."""
    encoded_chain = [c.pub.pem.encode() for c in chain]

    # Make sure that all PEMs end with a newline. RFC 7468 does not mandate a newline at the end, but it
    # seems in practice we always get one. We want to detect if that ever changes
    for member in encoded_chain:
        assert member.endswith(b"\n")

    bundle = cert.bundle_as_pem
    assert isinstance(bundle, str)
    assert bundle.endswith("\n")

    # Test the regex used by certbot to make sure certbot finds the expected certificates
    found = CERT_PEM_REGEX.findall(bundle.encode())
    assert encoded_chain == found
