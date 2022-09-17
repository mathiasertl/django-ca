# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca.  If not,
# see <http://www.gnu.org/licenses/>

# TYPEHINT NOTE: mypy-django typehints assertFieldOutput complete wrong.
# type: ignore

"""Test custom Django form fields."""


from cryptography import x509

from django.test import TestCase

from .. import fields
from .base.mixins import TestCaseMixin


class OCSPNoCheckFieldTestCase(TestCase, TestCaseMixin):
    """Tests for the OCSPNoCheckField."""

    def test_basic(self) -> None:
        """basic tests."""
        self.assertFieldOutput(
            fields.OCSPNoCheckField,
            {
                (True, True): self.ocsp_no_check(critical=True),
                (True, False): self.ocsp_no_check(critical=False),
                (False, False): None,
                (False, True): None,
            },
            {},
            empty_value=None,
        )


class TLSFeatureTestCase(TestCase, TestCaseMixin):
    """Tests for the TLSFeatureField."""

    def test_basic(self) -> None:
        """basic tests."""
        self.assertFieldOutput(
            fields.TLSFeatureField,
            {
                ((), False): None,
                ((), True): None,
                (("status_request",), False): self.tls_feature(x509.TLSFeatureType.status_request),
                (("status_request", "status_request_v2"), False): self.tls_feature(
                    x509.TLSFeatureType.status_request, x509.TLSFeatureType.status_request_v2
                ),
                (("status_request",), True): self.tls_feature(
                    x509.TLSFeatureType.status_request, critical=True
                ),
                (("status_request", "status_request_v2"), True): self.tls_feature(
                    x509.TLSFeatureType.status_request, x509.TLSFeatureType.status_request_v2, critical=True
                ),
            },
            {},
            empty_value=None,
        )
