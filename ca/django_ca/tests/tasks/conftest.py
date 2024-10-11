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

"""Minor assertions for tasks."""

from cryptography import x509

from django.core.cache import cache

from django_ca.models import CertificateAuthority
from django_ca.tests.base.utils import crl_cache_key


def assert_crl(ca: CertificateAuthority, crl: x509.CertificateRevocationList) -> None:
    """Test some basic characteristics of the CRL.

    .. NOTE:: Shorter version of main fixture, testing only some basic stuff.
    """
    if ca.algorithm is None:
        assert crl.signature_hash_algorithm is None
    else:
        assert isinstance(crl.signature_hash_algorithm, type(ca.algorithm))


def assert_crls(ca: CertificateAuthority) -> None:
    """Assert that the correct CRLs have been generated."""
    key = crl_cache_key(ca.serial, only_contains_ca_certs=True)
    crl = x509.load_der_x509_crl(cache.get(key))
    assert_crl(ca, crl)

    key = crl_cache_key(ca.serial, only_contains_user_certs=True)
    crl = x509.load_der_x509_crl(cache.get(key))
    assert_crl(ca, crl)
