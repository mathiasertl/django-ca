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

import copy
import warnings
from collections.abc import Iterable
from datetime import timedelta
from importlib.util import find_spec
from typing import Annotated, Any, Literal, Optional, Union, cast

from annotated_types import Ge, Le, MinLen
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator, model_validator

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from django.conf import settings as _settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.functional import Promise
from django.utils.translation import gettext_lazy as _

from django_ca import constants
from django_ca.deprecation import RemovedInDjangoCA220Warning
from django_ca.pydantic import NameModel
from django_ca.pydantic.type_aliases import (
    CertificateRevocationListEncodingTypeAlias,
    EllipticCurveTypeAlias,
    HashAlgorithmTypeAlias,
    PowerOfTwoInt,
    Serial,
    UniqueElementsTuple,
)
from django_ca.pydantic.validators import name_oid_parser, timedelta_as_number_parser
from django_ca.typehints import (
    AllowedHashTypes,
    CertificateRevocationListScopes,
    ConfigurableExtension,
    ConfigurableExtensionKeys,
    ParsableKeyType,
)

CRLEncodings = Annotated[frozenset[CertificateRevocationListEncodingTypeAlias], MinLen(1)]
# BeforeValidator currently does not work together with Le(), see:
#   https://github.com/pydantic/pydantic/issues/10459
# TimedeltaAsDays = Annotated[timedelta, BeforeValidator(timedelta_as_number_parser("days"))]
DayValidator = BeforeValidator(timedelta_as_number_parser("days"))
PositiveTimedelta = Annotated[timedelta, Ge(timedelta(days=1))]
AcmeCertValidity = Annotated[PositiveTimedelta, Le(timedelta(days=365)), DayValidator]

_DEFAULT_CA_PROFILES: dict[str, dict[str, Any]] = {
    "client": {
        # see: http://security.stackexchange.com/questions/68491/
        "description": _("A certificate for a client."),
        "extensions": {
            "key_usage": {
                "critical": True,
                "value": [
                    "digitalSignature",
                ],
            },
            "extended_key_usage": {
                "critical": False,
                "value": [
                    "clientAuth",
                ],
            },
        },
    },
    "server": {
        "description": _("A certificate for a server, allows client and server authentication."),
        "extensions": {
            "key_usage": {
                "critical": True,
                "value": [
                    "digitalSignature",
                    "keyAgreement",
                    "keyEncipherment",
                ],
            },
            "extended_key_usage": {
                "critical": False,
                "value": [
                    "clientAuth",
                    "serverAuth",
                ],
            },
        },
    },
    "webserver": {
        # see http://security.stackexchange.com/questions/24106/
        "description": _("A certificate for a webserver."),
        "extensions": {
            "key_usage": {
                "critical": True,
                "value": [
                    "digitalSignature",
                    "keyAgreement",
                    "keyEncipherment",
                ],
            },
            "extended_key_usage": {
                "critical": False,
                "value": [
                    "serverAuth",
                ],
            },
        },
    },
    "enduser": {
        # see: http://security.stackexchange.com/questions/30066/
        "description": _(
            "A certificate for an enduser, allows client authentication, code and email signing."
        ),
        "extensions": {
            "key_usage": {
                "critical": True,
                "value": [
                    "dataEncipherment",
                    "digitalSignature",
                    "keyEncipherment",
                ],
            },
            "extended_key_usage": {
                "critical": False,
                "value": [
                    "clientAuth",
                    "codeSigning",
                    "emailProtection",
                ],
            },
        },
    },
    "ocsp": {
        "description": _("A certificate for an OCSP responder."),
        "add_ocsp_url": False,
        "autogenerated": True,
        "subject": False,
        "extensions": {
            "key_usage": {
                "value": [
                    "nonRepudiation",
                    "digitalSignature",
                    "keyEncipherment",
                ],
            },
            "extended_key_usage": {
                "value": [
                    "OCSPSigning",
                ],
            },
            "ocsp_no_check": {},
        },
    },
}


def _check_name(name: x509.Name) -> None:
    # WARNING: This function is a duplicate of the function in utils.

    multiple_oids = (NameOID.DOMAIN_COMPONENT, NameOID.ORGANIZATIONAL_UNIT_NAME, NameOID.STREET_ADDRESS)

    seen = set()

    for attr in name:
        oid = attr.oid

        # Check if any fields are duplicate where this is not allowed (e.g. multiple CommonName fields)
        if oid in seen and oid not in multiple_oids:
            raise ImproperlyConfigured(
                f'{name}: Contains multiple "{constants.NAME_OID_NAMES[attr.oid]}" fields.'
            )

        value = attr.value
        if oid == NameOID.COMMON_NAME and (not value or len(value) > 64):  # pragma: only cryptography<43
            # Imitate message from cryptography 43
            raise ImproperlyConfigured(
                f"Value error, Attribute's length must be >= 1 and <= 64, but it was {len(attr.value)}"
            )

        seen.add(oid)


def _parse_deprecated_name_value(value: Any) -> Optional[x509.Name]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{value}: Must be a list or tuple.")

    name_attributes: list[x509.NameAttribute] = []
    for elem in value:
        if isinstance(elem, x509.NameAttribute):
            name_attributes.append(elem)
        elif isinstance(elem, (tuple, list)):
            if len(elem) != 2:
                raise ImproperlyConfigured(f"{elem}: Must be lists/tuples with two items, got {len(elem)}.")
            if not isinstance(elem[1], str):
                raise ImproperlyConfigured(f"{elem[1]}: Item values must be strings.")

            if isinstance(elem[0], x509.ObjectIdentifier):
                name_oid = elem[0]
            elif isinstance(elem[0], str):
                # name_oid_parser() always returns x509.ObjectedIdentifier for strings
                name_oid = cast(x509.ObjectIdentifier, name_oid_parser(elem[0]))
            else:
                raise ValueError(f"{elem[0]}: Must be a x509.ObjectIdentifier or str.")

            name_attribute = x509.NameAttribute(oid=name_oid, value=elem[1])
            name_attributes.append(name_attribute)
        else:
            raise ImproperlyConfigured(f"{elem}: Items must be a x509.NameAttribute, list or tuple.")

    normalized_name = x509.Name(name_attributes)
    _check_name(normalized_name)
    return normalized_name


def _subject_validator(value: Any) -> Any:
    try:
        return NameModel(value).cryptography
    except ValueError:
        parsed_value = _parse_deprecated_name_value(value)
        warnings.warn(
            f"{value}: Support for two-element tuples as subject is deprecated and will be removed in "
            f"django-ca 2.2.",
            RemovedInDjangoCA220Warning,
            stacklevel=2,
        )
        return parsed_value


Subject = Annotated[x509.Name, BeforeValidator(_subject_validator)]


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


class KeyBackendConfigurationModel(BaseModel):
    """Base model for a key backend configuration."""

    BACKEND: str
    OPTIONS: dict[str, Any] = Field(default_factory=dict)


class ProfileConfigurationModel(BaseModel):
    """Base model for profiles."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    description: Union[str, Promise] = ""
    subject: Optional[Union[Literal[False], Subject]] = None
    algorithm: Optional[AllowedHashTypes] = None
    extensions: dict[ConfigurableExtensionKeys, Optional[Union[dict[str, Any], ConfigurableExtension]]] = (
        Field(default_factory=dict)
    )
    expires: Optional[Annotated[PositiveTimedelta, DayValidator]] = None
    autogenerated: bool = False
    add_crl_url: bool = True
    add_ocsp_url: bool = True
    add_issuer_url: bool = True
    add_issuer_alternative_name: bool = True


class SettingsModel(BaseModel):
    """Pydantic model defining available settings."""

    model_config = ConfigDict(from_attributes=True, frozen=True, arbitrary_types_allowed=True)

    CA_ACME_ORDER_VALIDITY: Annotated[
        timedelta, Ge(timedelta(seconds=60)), Le(timedelta(days=1)), DayValidator
    ] = timedelta(hours=1)
    CA_ACME_DEFAULT_CERT_VALIDITY: AcmeCertValidity = timedelta(days=90)
    CA_ACME_MAX_CERT_VALIDITY: AcmeCertValidity = timedelta(days=90)

    CA_CRL_PROFILES: dict[str, CertificateRevocationListProfile] = {
        "user": CertificateRevocationListProfile(
            expires=timedelta(days=1), scope="user", encodings=[Encoding.PEM, Encoding.DER]
        ),
        "ca": CertificateRevocationListProfile(
            expires=timedelta(days=1), scope="ca", encodings=[Encoding.PEM, Encoding.DER]
        ),
    }
    CA_DEFAULT_CA: Optional[Serial] = None
    CA_DEFAULT_DSA_SIGNATURE_HASH_ALGORITHM: HashAlgorithmTypeAlias = hashes.SHA256()
    CA_DEFAULT_ELLIPTIC_CURVE: EllipticCurveTypeAlias = ec.SECP256R1()
    CA_DEFAULT_EXPIRES: Annotated[PositiveTimedelta, DayValidator] = timedelta(days=365)
    CA_DEFAULT_HOSTNAME: Optional[str] = None
    CA_DEFAULT_KEY_BACKEND: str = "default"
    CA_DEFAULT_KEY_SIZE: Annotated[PowerOfTwoInt, Ge(1024)] = 4096
    CA_DEFAULT_NAME_ORDER: UniqueElementsTuple[
        tuple[Annotated[x509.ObjectIdentifier, BeforeValidator(name_oid_parser)], ...]
    ] = (
        x509.NameOID.DN_QUALIFIER,
        x509.NameOID.COUNTRY_NAME,
        x509.NameOID.POSTAL_CODE,
        x509.NameOID.STATE_OR_PROVINCE_NAME,
        x509.NameOID.LOCALITY_NAME,
        x509.NameOID.DOMAIN_COMPONENT,
        x509.NameOID.ORGANIZATION_NAME,
        x509.NameOID.ORGANIZATIONAL_UNIT_NAME,
        x509.NameOID.TITLE,
        x509.NameOID.COMMON_NAME,
        x509.NameOID.USER_ID,
        x509.NameOID.EMAIL_ADDRESS,
        x509.NameOID.SERIAL_NUMBER,
    )
    CA_DEFAULT_PRIVATE_KEY_TYPE: ParsableKeyType = "RSA"
    CA_DEFAULT_PROFILE: str = "webserver"
    CA_DEFAULT_SIGNATURE_HASH_ALGORITHM: HashAlgorithmTypeAlias = hashes.SHA512()
    CA_DEFAULT_STORAGE_ALIAS: str = "django-ca"
    CA_DEFAULT_SUBJECT: Optional[Subject] = None
    CA_ENABLE_ACME: bool = True
    CA_ENABLE_REST_API: bool = False
    CA_KEY_BACKENDS: dict[str, KeyBackendConfigurationModel] = Field(default_factory=dict)
    CA_MIN_KEY_SIZE: Annotated[PowerOfTwoInt, Ge(1024)] = 2048
    CA_NOTIFICATION_DAYS: tuple[int, ...] = (14, 7, 3, 1)

    # The minimum value comes from the fact that the renewal task only runs every hour by default.
    CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL: Annotated[timedelta, Ge(timedelta(hours=2))] = timedelta(days=1)

    CA_PASSWORDS: dict[Serial, bytes] = Field(default_factory=dict)
    CA_PROFILES: dict[str, ProfileConfigurationModel] = Field(
        default_factory=lambda: {k: ProfileConfigurationModel(**v) for k, v in _DEFAULT_CA_PROFILES.items()}
    )
    CA_USE_CELERY: Annotated[bool, Field(default_factory=lambda: find_spec("celery") is not None)]

    @field_validator("CA_PROFILES", mode="before")
    @classmethod
    def parse_ca_profiles(cls, value: Any) -> Any:
        """Update the default CA profiles with the value from settings."""
        if isinstance(value, dict):
            profiles = copy.deepcopy(_DEFAULT_CA_PROFILES)
            for name, config in value.items():
                if config is None:
                    del profiles[name]
                    continue

                if name in profiles:
                    profiles[name].update(config)
                else:
                    profiles[name] = config
            return profiles
        return value

    @field_validator("CA_USE_CELERY", mode="before")
    @classmethod
    def validate_ca_use_celery(cls, value: Any) -> Any:
        """Validate that CA_USE_CELERY is not set if Celery is not installed, set if the value is not set."""
        spec = find_spec("celery")
        if value is True and spec is None:
            raise ValueError("CA_USE_CELERY set to True, but Celery is not installed")

        if value is None:
            # NOTE: The validator is only called if CA_USE_CELERY is explicitly set. The default value if the
            # field is **not** set at all is set in the default_factory of the model fields Field() function.
            return spec is not None
        return value

    @model_validator(mode="after")
    def check_ca_key_backends(self) -> "SettingsModel":
        """Set the default key backend if not set, and validate that the default key backend is configured."""
        if not self.CA_KEY_BACKENDS:
            # pylint: disable-next=unsupported-assignment-operation  # pylint this this is a Field()
            self.CA_KEY_BACKENDS[self.CA_DEFAULT_KEY_BACKEND] = KeyBackendConfigurationModel(
                BACKEND=constants.DEFAULT_STORAGE_BACKEND,
                OPTIONS={"storage_alias": self.CA_DEFAULT_STORAGE_ALIAS},
            )

        # pylint: disable-next=unsupported-membership-test  # pylint this this is a Field()
        elif self.CA_DEFAULT_KEY_BACKEND not in self.CA_KEY_BACKENDS:
            raise ValueError(f"{self.CA_DEFAULT_KEY_BACKEND}: The default key backend is not configured.")
        return self

    @model_validator(mode="after")
    def check_ca_default_profile(self) -> "SettingsModel":
        """Validate that the default profile is also configured."""
        # pylint: disable-next=unsupported-membership-test  # pylint this this is a Field()
        if self.CA_DEFAULT_PROFILE not in self.CA_PROFILES:
            raise ValueError(f"{self.CA_DEFAULT_PROFILE}: CA_DEFAULT_PROFILE is not defined as a profile.")
        return self

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
