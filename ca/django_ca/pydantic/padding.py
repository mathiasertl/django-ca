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

"""Padding algorithms."""

from typing import Annotated, Any, Literal

from pydantic import BeforeValidator, Field, model_validator

from cryptography.hazmat.primitives.asymmetric import padding

from django_ca.constants import HASH_ALGORITHM_TYPES
from django_ca.pydantic.base import CryptographyModel
from django_ca.pydantic.type_aliases import HashAlgorithmName


def pss_salt_length_validator(value: Any) -> Any:
    """Validator for the PSS salt length argument, converting constants to strings."""
    if value == padding.PSS.AUTO:
        return "AUTO"
    if value == padding.PSS.MAX_LENGTH:
        return "MAX_LENGTH"
    if value == padding.PSS.DIGEST_LENGTH:
        return "DIGEST_LENGTH"
    return value


class PKCS1v15Model(CryptographyModel[padding.PKCS1v15]):
    """Model for :class:`cg:~cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15`."""

    name: Literal["EMSA-PKCS1-v1_5"] = "EMSA-PKCS1-v1_5"

    @model_validator(mode="before")
    @classmethod
    def validate_cryptography(cls, obj: Any) -> Any:
        """Model validator to parse cryptography models."""
        if isinstance(obj, padding.PKCS1v15):
            return {}
        return obj

    @property
    def cryptography(self) -> padding.PKCS1v15:
        """Convert this model instance to a matching cryptography object."""
        return padding.PKCS1v15()


class MGF1Model(CryptographyModel[padding.MGF1]):
    """Model for :class:`cg:~cryptography.hazmat.primitives.asymmetric.padding.MGF1`."""

    algorithm: HashAlgorithmName

    @model_validator(mode="before")
    @classmethod
    def validate_cryptography(cls, obj: Any) -> Any:
        """Model validator to parse cryptography models."""
        if isinstance(obj, padding.MGF1):
            # pylint: disable-next=protected-access  # no public accessors available
            return {"algorithm": obj._algorithm}
        return obj

    @property
    def cryptography(self) -> padding.MGF1:
        """Convert this model instance to a matching cryptography object."""
        return padding.MGF1(algorithm=HASH_ALGORITHM_TYPES[self.algorithm]())


class PSSModel(CryptographyModel[padding.PSS]):
    """Model for :class:`cg:~cryptography.hazmat.primitives.asymmetric.padding.PSS`."""

    name: Literal["EMSA-PSS"] = "EMSA-PSS"
    salt_length: Annotated[
        int | Literal["MAX_LENGTH", "DIGEST_LENGTH", "AUTO"], BeforeValidator(pss_salt_length_validator)
    ]
    mgf: MGF1Model

    @model_validator(mode="before")
    @classmethod
    def validate_cryptography(cls, obj: Any) -> Any:
        """Model validator to parse cryptography models."""
        if isinstance(obj, padding.PSS):
            # pylint: disable-next=protected-access  # no public accessors available
            return {"mgf": MGF1Model(algorithm=obj.mgf._algorithm), "salt_length": obj._salt_length}
        return obj

    @property
    def cryptography(self) -> padding.PSS:
        """Convert this model instance to a matching cryptography object."""
        if self.salt_length == "MAX_LENGTH":
            salt_length: Any = padding.PSS.MAX_LENGTH
        elif self.salt_length == "DIGEST_LENGTH":
            salt_length = padding.PSS.DIGEST_LENGTH
        elif self.salt_length == "AUTO":
            salt_length = padding.PSS.AUTO
        else:
            salt_length = self.salt_length

        return padding.PSS(mgf=self.mgf.cryptography, salt_length=salt_length)


def padding_validator(value: Any) -> Any:
    """Validator for various padding types."""
    if isinstance(value, padding.PKCS1v15):
        return PKCS1v15Model.model_validate(value)
    if isinstance(value, padding.PSS):
        return PSSModel.model_validate(value)
    return value


AsymmetricPaddingTypes = Annotated[
    PKCS1v15Model | PSSModel, Field(discriminator="name"), BeforeValidator(padding_validator)
]
