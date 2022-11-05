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

"""Module providing extensions for x509 authorities supporting OpenSSH."""

import typing

from cryptography.x509 import Extension, ObjectIdentifier, UnrecognizedExtension

SSH_HOST_CA = ObjectIdentifier("1.2.22.2")
SSH_USER_CA = ObjectIdentifier("1.2.22.1")


if typing.TYPE_CHECKING:
    SshHostCaExtensionBase = Extension["SshHostCaType"]
    SshUserCaExtensionBase = Extension["SshUserCaType"]
else:
    SshHostCaExtensionBase = SshUserCaExtensionBase = Extension


class SshHostCaType(UnrecognizedExtension):
    """CA Certs with this extension can sign OpenSSH Host keys."""

    def __init__(self) -> None:
        super().__init__(SSH_HOST_CA, b"OpenSSH Host CA")


class SshHostCaExtension(SshHostCaExtensionBase):
    """Small wrapper class for an extension to use the SshHostCaType."""

    def __init__(self) -> None:
        super().__init__(SSH_HOST_CA, True, SshHostCaType())


class SshUserCaType(UnrecognizedExtension):
    """CA Certs with this extension can sign OpenSSH Client / User keys."""

    def __init__(self) -> None:
        super().__init__(SSH_USER_CA, b"OpenSSH User CA")


class SshUserCaExtension(SshUserCaExtensionBase):
    """Small wrapper class for an extension to use the SshUserCaType."""

    def __init__(self) -> None:
        super().__init__(SSH_USER_CA, True, SshUserCaType())
