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

import josepy as jose
from acme import fields, messages

identifiers_decoder = messages.Order._fields["identifiers"].fdec


class Order(messages.Order):
    """An object describing an ACME order.

    This class adds the not_before/not_after field to :py:class:`acme:acme.messages.Order`.
    """

    not_before = fields.RFC3339Field("notBefore", omitempty=True)
    not_after = fields.RFC3339Field("notAfter", omitempty=True)


class NewOrder(messages.ResourceBody):
    """An object describing a new order.

    This class differs from :py:class:`acme:acme.messages.NewOrder` in that the fields for this message are
    the subset of fields described for the ``newOrder`` resource in RFC 8555, section 7.4. Unlike in the ACME
    class, the `identifiers` field is mandatory, while the `not_before` and `not_after` fields are added.

    .. seealso:: `RFC 8555, section 7.4 <https://tools.ietf.org/html/rfc8555#section-7.4>`__
    """

    resource_type = "new-order"

    identifiers = jose.json_util.Field("identifiers", omitempty=False, decoder=identifiers_decoder)
    not_before = fields.RFC3339Field("notBefore", omitempty=True)
    not_after = fields.RFC3339Field("notAfter", omitempty=True)


class CertificateRequest(messages.ResourceBody):
    """ACME message expected when finalizing an order.

    This class differs from :py:class:`acme:acme.messages.CertificateRequest` in that it does not set the
    resource type.

    .. seealso:: `RFC 8555, section 7.4 <https://tools.ietf.org/html/rfc8555#section-7.4>`__
    """

    resource_type = "new-cert"
    csr = jose.json_util.Field("csr", decoder=jose.json_util.decode_csr, encoder=jose.json_util.encode_csr)
