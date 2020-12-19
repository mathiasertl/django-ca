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

"""Some constants from the ACME and associated standards.

.. WARNING::

   Do **not** import anything from acme or josepy here. This module is imported by various modules in the main
   django-ca library. Importing acme/josepy would make them a non-optional dependency.
"""

import enum
import string

# WARNING: Do not import acme or josepy, see above.

# base64url alphabet is defined in RFC 4648, section 5:
#   https://tools.ietf.org/html/rfc4648#section-5
# Jose JWS defines that the padding character ('=') is stripped:
#   https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-37#section-2
BASE64_URL_ALPHABET = string.ascii_letters + string.digits + '-_'


@enum.unique
class Status(enum.Enum):
    """Enum of possible statuses for ACME objects.

    Duplicates :py:class:`~acme:acme.messages.Status` to avoid required ``acme`` during model import.
    """
    UNKNOWN = 'unknown'
    PENDING = 'pending'
    PROCESSING = 'processing'
    VALID = 'valid'
    INVALID = 'invalid'
    REVOKED = 'revoked'
    READY = 'ready'
    DEACTIVATED = 'deactivated'
    EXPIRED = 'expired'  # NOTE: not present in acme 1.9.0


@enum.unique
class IdentifierType(enum.Enum):
    """Enum of possible identifier types.

    Duplicates :py:class:`~acme:acme.messages.IdentifierType` to avoid required ``acme`` during model import.
    """
    DNS = 'dns'  # equivalent to acme.messages.IDENTIFIER_FQDN
