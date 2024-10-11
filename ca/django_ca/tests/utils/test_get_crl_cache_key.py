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

"""Test :py:func:`~django_ca.utils.get_crl_cache_key` function."""

from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

import pytest

from django_ca.utils import get_crl_cache_key

DEFAULT_KWARGS = {
    "serial": "123",
    "encoding": Encoding.DER,
    "only_contains_ca_certs": False,
    "only_contains_user_certs": False,
    "only_contains_attribute_certs": False,
    "only_some_reasons": None,
}


@pytest.mark.parametrize(
    "kwargs,expected",
    (
        (DEFAULT_KWARGS, "crl_123_DER_False_False_False_None"),
        ({**DEFAULT_KWARGS, "encoding": Encoding.PEM}, "crl_123_PEM_False_False_False_None"),
        ({**DEFAULT_KWARGS, "only_contains_ca_certs": True}, "crl_123_DER_True_False_False_None"),
        ({**DEFAULT_KWARGS, "only_contains_user_certs": True}, "crl_123_DER_False_True_False_None"),
        ({**DEFAULT_KWARGS, "only_contains_attribute_certs": True}, "crl_123_DER_False_False_True_None"),
        (
            {
                **DEFAULT_KWARGS,
                "only_some_reasons": [x509.ReasonFlags.key_compromise, x509.ReasonFlags.aa_compromise],
            },
            "crl_123_DER_False_False_False_aa_compromise,key_compromise",
        ),
    ),
)
def test_function(kwargs: dict[str, Any], expected: str) -> None:
    """Test generating a cache key."""
    assert get_crl_cache_key(**kwargs) == expected
