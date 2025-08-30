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

"""EC algorithms."""

from typing import Any

from pydantic import model_validator

from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

from django_ca.constants import SIGNATURE_HASH_ALGORITHM_TYPES
from django_ca.pydantic.base import CryptographyModel
from django_ca.pydantic.type_aliases import AnnotatedSignatureHashAlgorithmName


class ECDSAModel(CryptographyModel[ECDSA]):
    """Model for :class:`cg:~cryptography.hazmat.primitives.asymmetric.ec.ECDSA`."""

    algorithm: AnnotatedSignatureHashAlgorithmName
    deterministic_signing: bool

    @model_validator(mode="before")
    @classmethod
    def validate_cryptography(cls, obj: Any) -> Any:
        """Model validator to parse cryptography models."""
        if isinstance(obj, ECDSA):
            return {"algorithm": obj.algorithm, "deterministic_signing": obj.deterministic_signing}
        return obj

    @property
    def cryptography(self) -> ECDSA:
        """Convert this model instance to a matching cryptography object."""
        return ECDSA(
            algorithm=SIGNATURE_HASH_ALGORITHM_TYPES[self.algorithm](),
            deterministic_signing=self.deterministic_signing,
        )
