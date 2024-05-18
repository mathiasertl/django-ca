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

"""Application configuration for django-ca."""

from collections.abc import Iterable
from datetime import timedelta
from typing import Annotated, Any, Optional

from annotated_types import Ge, Le, MinLen
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, model_validator

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding

from django.conf import settings as _settings
from django.core.exceptions import ImproperlyConfigured

from django_ca.pydantic.type_aliases import (
    CertificateRevocationListEncodingTypeAlias,
    EllipticCurveTypeAlias,
    PowerOfTwoInt,
    Serial,
)
from django_ca.pydantic.validators import timedelta_as_number_parser
from django_ca.typehints import CertificateRevocationListScopes, ParsableKeyType

CRLEncodings = Annotated[frozenset[CertificateRevocationListEncodingTypeAlias], MinLen(1)]
TimedeltaAsDays = Annotated[timedelta, BeforeValidator(timedelta_as_number_parser("days"))]


class CertificateRevocationListProfileOverride(BaseModel):
    """Model for overriding fields of a CRL Profile."""

    encodings: Optional[CRLEncodings] = None
    expires: Optional[timedelta] = None
    scope: Optional[CertificateRevocationListScopes] = None
    skip: bool = False


class CertificateRevocationListProfile(BaseModel):
    """Model for profiles for CRL generation."""

    encodings: CRLEncodings
    expires: timedelta = timedelta(days=1)
    scope: Optional[CertificateRevocationListScopes] = None
    OVERRIDES: dict[Serial, CertificateRevocationListProfileOverride] = Field(default_factory=dict)


class SettingsModel(BaseModel):
    """Pydantic model defining available settings."""

    model_config = ConfigDict(from_attributes=True, frozen=True)

    CA_ACME_ORDER_VALIDITY: Annotated[TimedeltaAsDays, Ge(timedelta(seconds=60)), Le(timedelta(days=1))] = (
        timedelta(hours=1)
    )
    CA_ACME_DEFAULT_CERT_VALIDITY: Annotated[
        TimedeltaAsDays, Ge(timedelta(days=1)), Le(timedelta(days=365))
    ] = timedelta(days=90)
    CA_ACME_MAX_CERT_VALIDITY: Annotated[TimedeltaAsDays, Ge(timedelta(days=1)), Le(timedelta(days=365))] = (
        timedelta(days=90)
    )

    CA_CRL_PROFILES: dict[str, CertificateRevocationListProfile] = {
        "user": CertificateRevocationListProfile(
            expires=timedelta(days=1), scope="user", encodings=[Encoding.PEM, Encoding.DER]
        ),
        "ca": CertificateRevocationListProfile(
            expires=timedelta(days=1), scope="ca", encodings=[Encoding.PEM, Encoding.DER]
        ),
    }
    CA_DEFAULT_CA: Optional[Serial] = None
    CA_DEFAULT_ELLIPTIC_CURVE: EllipticCurveTypeAlias = ec.SECP256R1()
    CA_DEFAULT_HOSTNAME: Optional[str] = None
    CA_DEFAULT_KEY_SIZE: PowerOfTwoInt = 4096
    CA_DEFAULT_PRIVATE_KEY_TYPE: ParsableKeyType = "RSA"
    CA_ENABLE_ACME: bool = True
    CA_ENABLE_REST_API: bool = False
    CA_MIN_KEY_SIZE: PowerOfTwoInt = 2048
    CA_NOTIFICATION_DAYS: tuple[int, ...] = (14, 7, 3, 1)

    # The minimum value comes from the fact that the renewal task only runs every hour by default.
    CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL: Annotated[timedelta, Ge(timedelta(hours=2))] = timedelta(days=1)

    @model_validator(mode="after")
    def check_min_key_size(self) -> "SettingsModel":
        """Validate that the minimum key size is not larger than the default key size."""
        if self.CA_MIN_KEY_SIZE > self.CA_DEFAULT_KEY_SIZE:
            raise ValueError(f"CA_DEFAULT_KEY_SIZE cannot be lower then {self.CA_MIN_KEY_SIZE}")
        return self


class SettingsProxy:
    """Proxy class to access settings from the model.

    This class exists to enable reloading of settings in test cases.
    """

    __settings: SettingsModel

    def __init__(self) -> None:
        self.reload()

    def __dir__(self, object: Any = None) -> Iterable[str]:  # pylint: disable=redefined-builtin
        # Used by ipython for tab completion, see:
        #   http://ipython.org/ipython-doc/dev/config/integrating.html
        return list(super().__dir__()) + list(self.__settings.model_fields)

    def reload(self) -> None:
        """Reload settings model from django settings."""
        try:
            self.__settings = SettingsModel.model_validate(_settings)
        except ValueError as ex:
            raise ImproperlyConfigured(str(ex)) from ex

    def __getattr__(self, item: str) -> Any:
        return getattr(self.__settings, item)


model_settings = SettingsProxy()
