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
# see <http://www.gnu.org/licenses/>.

"""Helper classes for spell checking.

.. seealso:: https://sphinxcontrib-spelling.readthedocs.io/en/latest/customize.html
"""

import re
import typing

from enchant.tokenize import Filter
from enchant.tokenize import URLFilter

from django_ca import typehints
from django_ca.extensions import KEY_TO_EXTENSION
from django_ca.extensions import ExtendedKeyUsage
from django_ca.extensions import KeyUsage


class URIFilter(URLFilter):
    """Overwrite URIFilter to only allow http/https URLs."""

    _pattern = re.compile(r"URI:https?://[^\s]*")


class MagicWordsFilter(Filter):
    """Filter for a few magic words.

    This filter adds a few product names and keywords, as well as known extension names and
    KeyUsage/ExtendedKeyUsage values.

    Note that filters are case sensitive, so adding keys here is also more restrictive then a wordlist and
    ensures canonical spelling. Filters are also a bit more inclusive, e.g. ``django-ca`` is not a single word
    in a wordlist but can be dropped here.
    """

    words = {
        "GoDaddy",
        "TrustID",
        "Comodo",
        "IdenTrust",
        "cRLNumber",
        "caIssuers",
        "Pre-Authorization",  # term from ACME, don't remove "-" here
        "Precertificate",
        "Django",
        "Djangos",
        "IPv4",
        "IPv6",
        "django-ca",
        "uWSGI",
        "Kubernetes",
        "NGINX",  # homepage consistently uses all caps
        ".ini",
        "base64url",
        "LibreSSL",
        "OpenSSL",
        "pyOpenSSL",
        "libffi",
        "SystemD",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.words |= KeyUsage.CRYPTOGRAPHY_MAPPING.keys()
        self.words |= ExtendedKeyUsage.CRYPTOGRAPHY_MAPPING.keys()
        self.words |= {e.name for e in KEY_TO_EXTENSION.values()}

    def _skip(self, word):
        return word in self.words


class TypeHintsFilter(Filter):
    """Filter ``typing.TypeVar`` instances in :py:mod:`~django_ca.typehints` as known words.

    Return type annotations that are actually ``typing.TypeVar`` are not recognized as such. Sphinx also
    doesn't link them properly in HTML. This appears to also make them show up as spelling errors.
    """

    typehints = [
        str(getattr(typehints, tv))
        for tv in dir(typehints)
        if isinstance(getattr(typehints, tv), typing.TypeVar)
    ]

    def _skip(self, word):
        return word in self.typehints
