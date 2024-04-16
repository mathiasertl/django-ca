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

"""Model for GeneralName subclasses."""

import binascii
import ipaddress
from datetime import datetime
from ipaddress import ip_address, ip_network
from typing import Annotated, Any, Optional, Union, cast

from pydantic import BeforeValidator, Discriminator, Tag, TypeAdapter, model_validator

import asn1crypto.core
from cryptography import x509

from django_ca import constants
from django_ca.pydantic import validators
from django_ca.pydantic.base import CryptographyModel
from django_ca.pydantic.name import NameModel
from django_ca.pydantic.type_aliases import OIDType
from django_ca.typehints import GeneralNames, IPAddressType, OtherNames

ip_address_classes = (
    ipaddress.IPv4Address,
    ipaddress.IPv6Address,
    ipaddress.IPv4Network,
    ipaddress.IPv6Network,
)


def general_name_discriminator(value: Any) -> Optional[str]:
    """Decide on the discriminated type for a GeneralName value."""
    if isinstance(value, ip_address_classes):
        return "ipaddress"
    if isinstance(value, str):
        return "str"
    if isinstance(value, (list, NameModel)):
        return "name"
    if isinstance(value, (dict, OtherNameModel)):
        return "othername"
    return "str"


def other_name_type_aliases(value: Any) -> Any:
    """Validator to convert OtherName aliases."""
    return constants.OTHER_NAME_ALIASES.get(value, value)


class OtherNameModel(CryptographyModel[x509.OtherName]):
    """Pydantic model wrapping :py:class:`~cg:cryptography.x509.OtherName`.

    The `oid` argument may be any valid object identifier as dotted string (e.g. ``"1.2.3"``).

    The `type` argument may be any type in :py:attr:`~django_ca.constants.OTHER_NAME_TYPES` or
    :py:class:`~django_ca.constants.OTHER_NAME_ALIASES`.

    The type of the `value` argument depends on the `type` value. String variants (``UTFString``, etc.)
    require a ``str``, boolean requires a ``bool`` value and so on:

    .. pydantic-model:: othername

    For datetime variants (``UTCTIME`` and ``GENERALIZEDTIME``), you must pass a timezone-aware object:

    .. pydantic-model:: othername_utctime

    For ``INTEGER``, you can pass an ``int`` or a ``str`` for a base 16 integer:

    .. pydantic-model:: othername_integer

    Finally, for an ``OctetString``, pass the raw bytes or as a hex-encoded string:

    .. pydantic-model:: othername_octetstring

    As usual, the ``cryptography`` property will return the cryptography variant of the model:

    >>> OtherNameModel(oid="1.2.3", type="IA5STRING", value="some string").cryptography
    <OtherName(type_id=<ObjectIdentifier(oid=1.2.3, name=Unknown OID)>, value=b'\\x16\\x0bsome string')>
    """

    oid: OIDType
    type: Annotated[OtherNames, BeforeValidator(other_name_type_aliases)]
    value: Optional[Union[str, bool, datetime, int]]

    @classmethod
    def _parse_bytes(cls, value: bytes) -> str:
        return binascii.hexlify(value).upper().decode("ascii")

    @model_validator(mode="before")
    @classmethod
    def parse_cryptography(cls, data: Any) -> Any:
        """Parse cryptography instances."""
        if isinstance(data, x509.OtherName):
            try:
                value = asn1crypto.core.load(data.value)
            except ValueError as ex:
                raise ValueError(f"could not parse asn1 data: {ex}") from ex

            if name_type := constants.OTHER_NAME_NAMES.get(type(value)):
                name_value = value.native

                if isinstance(value, asn1crypto.core.OctetString):
                    name_value = cls._parse_bytes(name_value)

                return {"oid": data.type_id.dotted_string, "type": name_type, "value": name_value}

            raise ValueError(f"{value.tag}: Unknown otherName type found.")

        if isinstance(data, dict) and data.get("type") == "OctetString":
            if isinstance(data.get("value"), bytes):
                data["value"] = cls._parse_bytes(data["value"])

        return data

    @model_validator(mode="after")
    def check_consistency(self) -> "OtherNameModel":
        """Validator to check that the `type` matches the type of `value`."""
        if self.type in ("UTF8String", "UNIVERSALSTRING", "IA5STRING") and not isinstance(self.value, str):
            raise ValueError(f"{self.type}: Value must be a str object.")
        if self.type == "BOOLEAN" and not isinstance(self.value, bool):
            raise ValueError(f"{self.type}: Value must be a boolean.")
        if self.type in ("UTCTIME", "GENERALIZEDTIME") and not isinstance(self.value, datetime):
            raise ValueError(f"{self.type}: Value must be a datetime object.")
        if self.type == "INTEGER":
            if isinstance(self.value, str):
                if self.value.startswith("0x"):
                    self.value = int(self.value, 16)
                else:
                    try:
                        self.value = int(self.value)
                    except ValueError:
                        pass

            if not isinstance(self.value, int):
                raise ValueError(f"{self.type}: Value must be an int.")
        if self.type == "NULL" and self.value is not None:
            raise ValueError(f"{self.type}: Value must be None.")
        if self.type == "OctetString" and not isinstance(self.value, str):
            raise ValueError(f"{self.type}: Value must be a str object.")
        return self

    @property
    def cryptography(self) -> x509.OtherName:
        """Convert to a :py:class:`~cg:cryptography.x509.OtherName` instance."""
        if self.type == "OctetString":
            hex_value = cast(str, self.value)  # asserted by the validator
            value = asn1crypto.core.OctetString(bytes(bytearray.fromhex(hex_value))).dump()
        elif asn1_cls := constants.OTHER_NAME_TYPES.get(self.type):
            value = asn1_cls(self.value).dump()
        else:  # pragma: no cover  # we cover all cases
            raise ValueError(f"{self.type}: Unknown type")

        return x509.OtherName(type_id=x509.ObjectIdentifier(self.oid), value=value)


class GeneralNameModel(CryptographyModel[x509.GeneralName]):
    """Pydantic model wrapping :py:class:`~cg:cryptography.x509.NameAttribute`.

    This model takes a `type` named in :py:attr:`~django_ca.constants.GENERAL_NAME_TYPES` and a `value` that
    is usually a ``str``:

    .. pydantic-model:: general_name

    For directory names, you have to pass a :py:class:`~django_ca.pydantic.name.NameModel` instead:

    .. pydantic-model:: general_name_name

    For :py:class:`~cg:cryptography.x509.OtherName` instances, pass a
    :py:class:`~django_ca.pydantic.general_name.OtherNameModel` instead:

    .. pydantic-model:: general_name_othername
       :cryptography-prefix: othername
    """

    type: GeneralNames

    # Use a discriminated Union so that pydantic can more efficiently determine the type. Without
    # discrimination, passing large IPv4/IPv6 networks (which are iterable, just like a list of str intended
    # for NameModel) would invoke the NameAttribute validation for every address in the network, making this
    # extremely slow for large network segments.
    value: Annotated[
        Union[
            Annotated[str, Tag("str")],
            Annotated[NameModel, Tag("name")],
            Annotated[OtherNameModel, Tag("othername")],
            Annotated[IPAddressType, Tag("ipaddress")],
        ],
        Discriminator(general_name_discriminator),
    ]

    @model_validator(mode="before")
    @classmethod
    def parse_cryptography(cls, data: Any) -> Any:
        """Validator to parse cryptography values."""
        if isinstance(data, x509.RegisteredID):
            return {"type": "RID", "value": data.value.dotted_string}
        if isinstance(data, x509.OtherName):
            return {"type": "otherName", "value": OtherNameModel.model_validate(data)}
        if isinstance(data, x509.DirectoryName):
            return {"type": "dirName", "value": list(data.value)}
        if isinstance(data, x509.GeneralName):  # email, URI, DNS, IPAddress
            type_value = constants.GENERAL_NAME_NAMES[type(data)]
            return {"type": type_value, "value": data.value}

        return data

    @model_validator(mode="after")
    def validate_value(self) -> "GeneralNameModel":
        """Validator to make sure that `value` is of the right type."""
        if self.type == "URI":
            if not isinstance(self.value, str):
                raise ValueError(f"{self.value}: Must be a str for type {self.type}")

            self.value = validators.url_validator(self.value)
        elif self.type == "email":
            if not isinstance(self.value, str):
                raise ValueError(f"{self.value}: Must be a str for type {self.type}")

            self.value = validators.email_validator(self.value)
        elif self.type == "IP":
            if isinstance(self.value, str):
                try:
                    self.value = ip_address(self.value)
                except ValueError:
                    try:
                        self.value = ip_network(self.value)
                    except ValueError as ex:
                        raise ValueError(f"{self.value}: Could not parse IP address") from ex

            elif not isinstance(self.value, ip_address_classes):
                raise ValueError(f"{self.value}: Must be an IPAddress/IPNetwork for type {self.type}")

        elif self.type == "RID":
            if not isinstance(self.value, str):
                raise ValueError(f"{self.value}: Must be a str for type {self.type}")

            validators.oid_validator(self.value)
        elif self.type == "otherName":
            if not isinstance(self.value, OtherNameModel):
                raise ValueError(f"{self.value}: Must be OtherNameModel for type {self.type}")
        elif self.type == "DNS":
            if not isinstance(self.value, str):
                raise ValueError(f"{self.value}: Must be a str for type {self.type}")

            self.value = validators.dns_validator(self.value)
        elif self.type == "dirName":
            pass
        else:
            raise ValueError(f"{self.type}: Unknown type")  # pragma: no cover

        return self

    @property
    def cryptography(self) -> x509.GeneralName:
        """Convert to a :py:class:`~cg:cryptography.x509.GeneralName` instance."""
        if self.type == "RID":
            if not isinstance(self.value, str):  # pragma: no cover  # just to make mypy happy
                raise ValueError(f"{self.value}: Must be a str for type {self.type}")

            return x509.RegisteredID(x509.ObjectIdentifier(self.value))
        if self.type == "dirName":
            if not isinstance(self.value, NameModel):  # pragma: no cover  # just to make mypy happy
                raise ValueError(f"{self.value}: Must be a str for type {self.type}")

            return x509.DirectoryName(self.value.cryptography)
        if self.type == "otherName":
            if not isinstance(self.value, OtherNameModel):  # pragma: no cover  # just to make mypy happy
                raise ValueError(f"{self.value}: Must be a OtherNameModel for type {self.type}")

            return self.value.cryptography

        # TYPEHINT NOTE: constant has type GeneralName, abstract constructor does not take arguments
        return constants.GENERAL_NAME_TYPES[self.type](self.value)  # type: ignore[call-arg]


GeneralNameModelList = TypeAdapter(list[GeneralNameModel])
