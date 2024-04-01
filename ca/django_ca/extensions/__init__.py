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

"""Extension classes wrapping various X.509 extensions.

The classes in this module wrap cryptography extensions, but allow adding/removing values, creating extensions
in a more pythonic manner and provide access functions.
"""

from cryptography import x509
from cryptography.hazmat._oid import _OID_NAMES as OID_NAMES

from django_ca.constants import EXTENSION_NAMES
from django_ca.extensions.parse import parse_extension
from django_ca.extensions.text import extension_as_text


def get_extension_name(oid: x509.ObjectIdentifier) -> str:
    """Function to get the name of an extension from the extensions OID.

    >>> from cryptography.x509.oid import ExtensionOID
    >>> get_extension_name(ExtensionOID.BASIC_CONSTRAINTS)
    'Basic Constraints'
    >>> get_extension_name(x509.ObjectIdentifier("1.2.3"))
    'Unknown extension (1.2.3)'

    """
    if oid in EXTENSION_NAMES:
        return EXTENSION_NAMES[oid]

    return OID_NAMES.get(oid, f"Unknown extension ({oid.dotted_string})")


__all__ = ["extension_as_text", "get_extension_name", "parse_extension"]
