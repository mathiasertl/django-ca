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

"""Some constants from the ACME and associated standards."""

import string

# base64url alphabet is defined in RFC 4648, section 5:
#   https://tools.ietf.org/html/rfc4648#section-5
# Jose JWS defines that the padding character ('=') is stripped:
#   https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-37#section-2
BASE64_URL_ALPHABET = string.ascii_letters + string.digits + '-_'
