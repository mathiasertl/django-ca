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

"""Specialized variants of ACME message classes."""

# pylint: disable=unsubscriptable-object; https://github.com/PyCQA/pylint/issues/3882

from typing import TYPE_CHECKING
from typing import List

import josepy as jose
from acme import fields
from acme import messages

# https://mypy.readthedocs.io/en/stable/runtime_troubles.html#using-classes-that-are-generic-in-stubs-but-not-at-runtime
if TYPE_CHECKING:
    IdentifiersType = jose.Field[List[str]]
else:
    IdentifiersType = jose.Field


class Order(messages.Order):
    """An object describing an ACME order.

    This class adds the not_before/not_after field to :py:class:`acme:acme.messages.Order`.
    """

    not_before = fields.RFC3339Field('notBefore', omitempty=True)
    not_after = fields.RFC3339Field('notAfter', omitempty=True)


class NewOrder(messages.ResourceBody):
    """An object describing a new order.

    This class differs from :py:class:`acme:acme.messages.NewOrder` in that the fields for this message are
    the subset of fields described for the ``newOrder`` resource in RFC 8555, section 7.4. Unlike in the ACME
    class, the `identifiers` field is mandatory, while the `not_before` and `not_after` fields are added.

    .. seealso:: `RFC 8555, section 7.4 <https://tools.ietf.org/html/rfc8555#section-7.4>`__
    """
    resource_type = messages.NewOrder.resource_type

    identifiers: IdentifiersType = jose.Field(
        'identifiers', omitempty=False,
        decoder=messages.Order._fields['identifiers'].fdec
    )
    not_before = fields.RFC3339Field('notBefore', omitempty=True)
    not_after = fields.RFC3339Field('notAfter', omitempty=True)
