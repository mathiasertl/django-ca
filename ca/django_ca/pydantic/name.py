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

"""Model for x509.Name."""

import base64
from typing import Annotated, Any, cast

from pydantic import BeforeValidator, ConfigDict, Field, model_validator

from cryptography import x509
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import NameOID

from django_ca import constants
from django_ca.pydantic import validators
from django_ca.pydantic.base import CryptographyModel, CryptographyRootModel
from django_ca.pydantic.type_aliases import OIDType

_NAME_ATTRIBUTE_OID_DESCRIPTION = (
    "A dotted string representing the OID or a known alias as described in "
    "[NAME_OID_TYPES]"
    "(https://django-ca.readthedocs.io/en/latest/python/constants.html#django_ca.constants.NAME_OID_TYPES)."
)
_NAME_ATTRIBUTE_VALUE_DESCRIPTION = (
    "Actual value of the attribute. For x500 unique identifiers (OID "
    f"{NameOID.X500_UNIQUE_IDENTIFIER.dotted_string}) the value must be the base64 encoded."
)


class NameAttributeModel(CryptographyModel[x509.NameAttribute]):
    """Pydantic model wrapping :py:class:`~cg:cryptography.x509.NameAttribute`.

    For the `oid`, you can either use a dotted string or an alias from
    :py:attr:`~django_ca.constants.NAME_OID_TYPES`:

    .. pydantic-model:: name_attribute

    When processing a x500 unique identifier attribute, the value is expected to be base64 encoded:

    .. pydantic-model:: name_attribute_x500
    """

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "description": "A NameAttribute is defined by an object identifier (OID) and a value."
        },
    )

    oid: Annotated[OIDType, BeforeValidator(validators.name_oid_dotted_string_parser)] = Field(
        title="Object identifier",
        description=_NAME_ATTRIBUTE_OID_DESCRIPTION,
        json_schema_extra={"example": NameOID.COMMON_NAME.dotted_string},
    )
    value: str = Field(
        description=_NAME_ATTRIBUTE_VALUE_DESCRIPTION,
        json_schema_extra={"example": "example.com"},
    )

    @model_validator(mode="before")
    @classmethod
    def parse_cryptography(cls, data: Any) -> Any:
        """Validator to handle x500 unique identifiers."""
        if isinstance(data, x509.NameAttribute) and data.oid == NameOID.X500_UNIQUE_IDENTIFIER:
            value = cast(bytes, data.value)
            return {"oid": data.oid.dotted_string, "value": base64.b64encode(value).decode("ascii")}
        return data

    @model_validator(mode="after")
    def validate_name_attribute(self) -> "NameAttributeModel":
        """Validate that country code OIDs have exactly two characters."""
        country_code_oids = (
            NameOID.COUNTRY_NAME.dotted_string,
            NameOID.JURISDICTION_COUNTRY_NAME.dotted_string,
        )
        if self.oid in country_code_oids and len(self.value) != 2:
            raise ValueError(f"{self.value}: Must have exactly two characters")

        if self.oid == NameOID.COMMON_NAME.dotted_string and not self.value:
            name = constants.NAME_OID_NAMES[NameOID.COMMON_NAME]
            raise ValueError(f"{name} must not be an empty value")
        return self

    @property
    def cryptography(self) -> x509.NameAttribute:
        """The :py:class:`~cg:cryptography.x509.NameAttribute` instance for this model."""
        oid = x509.ObjectIdentifier(self.oid)
        if oid == NameOID.X500_UNIQUE_IDENTIFIER:
            value = base64.b64decode(self.value)
            return x509.NameAttribute(oid=oid, value=value, _type=_ASN1Type.BitString)

        return x509.NameAttribute(oid=oid, value=self.value)


class NameModel(CryptographyRootModel[list[NameAttributeModel], x509.Name]):
    """Pydantic model wrapping :py:class:`~cg:cryptography.x509.Name`.

    This model is a Pydantic :py:class:`~pydantic.root_model.RootModel` that takes a list of
    :py:class:`~django_ca.pydantic.name.NameAttributeModel` instances:

    .. pydantic-model:: name
    """

    root: list[NameAttributeModel] = Field(
        json_schema_extra={
            "format": "X.501 Name",
            "example": [
                {"oid": NameOID.COUNTRY_NAME.dotted_string, "value": "AT"},
                {"oid": NameOID.COMMON_NAME.dotted_string, "value": "example.com"},
            ],
            "description": "A Name is composed of a list of name attributes.",
        },
    )

    @model_validator(mode="before")
    @classmethod
    def parse_cryptography(cls, data: Any) -> Any:
        """Validator for parsing :py:class:`~cg:cryptography.x509.Name`."""
        if isinstance(data, x509.Name):
            return list(data)
        return data

    @model_validator(mode="after")
    def validate_duplicates(self) -> "NameModel":
        """Validator to make sure that OIDs do not occur multiple times."""
        seen = set()

        # for oid in set(oids):
        for attr in self.root:
            oid = x509.ObjectIdentifier(attr.oid)

            # Check if any fields are duplicate where this is not allowed (e.g. multiple CommonName fields)
            if oid in seen and oid not in constants.MULTIPLE_OIDS:
                name = constants.NAME_OID_NAMES.get(oid, oid.dotted_string)
                raise ValueError(f"attribute of type {name} must not occur more then once in a name.")
            seen.add(oid)
        return self

    @property
    def cryptography(self) -> x509.Name:
        """The :py:class:`~cg:cryptography.x509.Name` instance for this model."""
        return x509.Name([attr.cryptography for attr in self.root])
