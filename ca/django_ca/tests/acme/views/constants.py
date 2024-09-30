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

"""Constants for ACME tests."""

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from django_ca.tests.base.constants import CERT_DATA

SERVER_NAME = "example.com"
HOST_NAME = "example.com"  # todo: make this different
PEM = (
    CERT_DATA["root-cert"]["key"]["parsed"]
    .public_key()
    .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    .decode("utf-8")
    .strip()
)
THUMBPRINT = "kqtZjXqX07HbrRg220VoINzqF9QXsfIkQava3PdWM8o"