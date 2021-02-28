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


class URIFilter(URLFilter):
    _pattern = re.compile(r"URI:https?://[^\s]*")


class MagicWordsFilter(Filter):
    words = {
        "manage.py",
        "IPv4",
        "IPv6",
    }

    def _skip(self, word):
        return word in self.words


class TypeHintsFilter(Filter):
    """Filter ``typing.TypeVar`` instances in :py:mod:`~django_ca.typehints` as known words.

    Return type annotations that are actually ``typing.TypeVar`` are not recognized as such. Sphinx also
    doesn't link them properly in HTML. This appears to also make them show up as spelling errors.
    """
    typehints = [str(getattr(typehints, tv)) for tv in dir(typehints)
                 if isinstance(getattr(typehints, tv), typing.TypeVar)]

    def _skip(self, word):
        return word in self.typehints
