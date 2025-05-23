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
from collections.abc import Iterable
from datetime import timedelta
from importlib.util import find_spec
from typing import Annotated, Any, Generic, Literal, TypeVar

from annotated_types import Ge, Le
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from django.conf import settings as _settings
from django.core.exceptions import ImproperlyConfigured
from django.core.signals import setting_changed
from django.utils.functional import Promise
from django.utils.translation import gettext_lazy as _

from django_ca import constants
from django_ca.pydantic import NameModel
from django_ca.pydantic.type_aliases import (
    CertificateRevocationListReasonCode,
    EllipticCurveTypeAlias,
    HashAlgorithmTypeAlias,
    PowerOfTwoInt,
    Serial,
    UniqueElementsTuple,
)
from django_ca.pydantic.validators import crl_scope_validator, name_oid_parser, timedelta_as_number_parser
from django_ca.typehints import (
    AllowedHashTypes,
    ConfigurableExtension,
    ConfigurableExtensionKeys,
    ParsableKeyType,
    Self,
)

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


def _subject_validator(value: Any) -> Any:
    return NameModel(value).cryptography


Subject = Annotated[x509.Name, BeforeValidator(_subject_validator)]


class CertificateRevocationListBaseModel(BaseModel):
    """Base model for CRL profiles and overrides."""

    only_contains_ca_certs: bool = False
    only_contains_user_certs: bool = False
    only_contains_attribute_certs: bool = False
    only_some_reasons: frozenset[CertificateRevocationListReasonCode] | None = None

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        """Validate the scope of the CRL."""
        crl_scope_validator(
            self.only_contains_ca_certs,
            self.only_contains_user_certs,
            self.only_contains_attribute_certs,
            None,  # already validated by type alias for field
        )
        return self


class CertificateRevocationListProfileOverride(CertificateRevocationListBaseModel):
    """Model for overriding fields of a CRL Profile."""

    expires: timedelta | None = None
    skip: bool = False


class CertificateRevocationListProfile(CertificateRevocationListBaseModel):
    """Model for profiles for CRL generation."""

    expires: timedelta = timedelta(days=1)
    OVERRIDES: dict[Serial, CertificateRevocationListProfileOverride] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_overrides(self) -> Self:
        """Validate that overrides do not create an invalid scope."""
        # pylint: disable-next=no-member  # pylint doesn't recognize the type of OVERRIDES.
        for override in self.OVERRIDES.values():
            only_contains_user_certs = self.only_contains_user_certs
            only_contains_ca_certs = self.only_contains_ca_certs
            only_contains_attribute_certs = self.only_contains_attribute_certs
            if "only_contains_ca_certs" in override.model_fields_set:
                only_contains_ca_certs = override.only_contains_ca_certs
            if "only_contains_user_certs" in override.model_fields_set:
                only_contains_user_certs = override.only_contains_user_certs
            if "only_contains_attribute_certs" in override.model_fields_set:
                only_contains_attribute_certs = override.only_contains_attribute_certs

            crl_scope_validator(  # only_some_reasons is already validated by type alias for field
                only_contains_ca_certs, only_contains_user_certs, only_contains_attribute_certs, None
            )
        return self


class KeyBackendConfigurationModel(BaseModel):
    """Base model for a key backend configuration."""

    BACKEND: str
    OPTIONS: dict[str, Any] = Field(default_factory=dict)


class ProfileConfigurationModel(BaseModel):
    """Base model for profiles."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    description: str | Promise = ""
    subject: Literal[False] | Subject | None = None
    algorithm: AllowedHashTypes | None = None
    extensions: dict[ConfigurableExtensionKeys, dict[str, Any] | ConfigurableExtension | None] = Field(
        default_factory=dict
    )
    expires: Annotated[PositiveTimedelta, DayValidator] | None = None
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
        "user": CertificateRevocationListProfile(only_contains_user_certs=True),
        "ca": CertificateRevocationListProfile(only_contains_ca_certs=True),
    }
    CA_DEFAULT_CA: Serial | None = None
    CA_DEFAULT_DSA_SIGNATURE_HASH_ALGORITHM: HashAlgorithmTypeAlias = hashes.SHA256()
    CA_DEFAULT_ELLIPTIC_CURVE: EllipticCurveTypeAlias = ec.SECP256R1()
    CA_DEFAULT_EXPIRES: Annotated[PositiveTimedelta, DayValidator] = timedelta(days=365)
    CA_DEFAULT_HOSTNAME: str | None = None
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
    CA_DEFAULT_OCSP_KEY_BACKEND: str = "default"
    CA_DEFAULT_PRIVATE_KEY_TYPE: ParsableKeyType = "RSA"
    CA_DEFAULT_PROFILE: str = "webserver"
    CA_DEFAULT_SIGNATURE_HASH_ALGORITHM: HashAlgorithmTypeAlias = hashes.SHA512()
    CA_DEFAULT_STORAGE_ALIAS: str = "django-ca"
    CA_DEFAULT_SUBJECT: Subject | None = None
    CA_ENABLE_ACME: bool = True
    CA_ENABLE_REST_API: bool = False
    CA_KEY_BACKENDS: dict[str, KeyBackendConfigurationModel] = Field(default_factory=dict)
    CA_MIN_KEY_SIZE: Annotated[PowerOfTwoInt, Ge(1024)] = 2048
    CA_NOTIFICATION_DAYS: tuple[int, ...] = (14, 7, 3, 1)
    CA_OCSP_KEY_BACKENDS: dict[str, KeyBackendConfigurationModel] = Field(default_factory=dict)

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
            self.CA_KEY_BACKENDS[self.CA_DEFAULT_KEY_BACKEND] = KeyBackendConfigurationModel(
                BACKEND=constants.DEFAULT_STORAGE_BACKEND,
                OPTIONS={"storage_alias": self.CA_DEFAULT_STORAGE_ALIAS},
            )

        elif self.CA_DEFAULT_KEY_BACKEND not in self.CA_KEY_BACKENDS:
            raise ValueError(f"{self.CA_DEFAULT_KEY_BACKEND}: The default key backend is not configured.")
        return self

    @model_validator(mode="after")
    def check_ca_ocsp_key_backends(self) -> "SettingsModel":
        """Set the default OCSP key backend if not set, and validate that the default is configured."""
        if not self.CA_OCSP_KEY_BACKENDS:
            self.CA_OCSP_KEY_BACKENDS[self.CA_DEFAULT_OCSP_KEY_BACKEND] = KeyBackendConfigurationModel(
                BACKEND=constants.DEFAULT_OCSP_KEY_BACKEND,
                OPTIONS={"storage_alias": self.CA_DEFAULT_STORAGE_ALIAS},
            )

        elif self.CA_DEFAULT_OCSP_KEY_BACKEND not in self.CA_OCSP_KEY_BACKENDS:
            raise ValueError(f"{self.CA_DEFAULT_KEY_BACKEND}: The default key backend is not configured.")
        return self

    @model_validator(mode="after")
    def check_ca_default_profile(self) -> "SettingsModel":
        """Validate that the default profile is also configured."""
        if self.CA_DEFAULT_PROFILE not in self.CA_PROFILES:
            raise ValueError(f"{self.CA_DEFAULT_PROFILE}: CA_DEFAULT_PROFILE is not defined as a profile.")
        return self

    @model_validator(mode="after")
    def check_min_key_size(self) -> "SettingsModel":
        """Validate that the minimum key size is not larger than the default key size."""
        if self.CA_MIN_KEY_SIZE > self.CA_DEFAULT_KEY_SIZE:
            raise ValueError(f"CA_DEFAULT_KEY_SIZE cannot be lower then {self.CA_MIN_KEY_SIZE}")
        return self


BaseModelTypeVar = TypeVar("BaseModelTypeVar", bound=BaseModel)


class SettingsProxyBase(Generic[BaseModelTypeVar]):
    """Reusable Pydantic model proxy that reloads on automatically when settings change.

    Implementers must set `settings_model` to the Pydantic model they want to use.

    Parameters
    ----------
    reload_on_change : bool, optional
        Set to ``False`` if you do not want to reload the underlying model when settings change during
        testing.
    """

    settings_model: type[BaseModelTypeVar]
    __settings: BaseModelTypeVar

    def __init__(self, reload_on_change: bool = True) -> None:
        self.reload()

        # Connect signal handler to reload the underlying Pydantic model when settings change.
        if reload_on_change is True:  # pragma: no branch
            self._connect_settings_changed()

    def __dir__(self, object: Any = None) -> Iterable[str]:  # pylint: disable=redefined-builtin
        # Used by ipython for tab completion, see:
        #   http://ipython.org/ipython-doc/dev/config/integrating.html
        return list(super().__dir__()) + list(self.settings_model.model_fields)

    def _connect_settings_changed(self) -> None:
        setting_changed.connect(self._reload_from_signal)

    def _reload_from_signal(self, **kwargs: Any) -> None:
        self.reload()

    def reload(self) -> None:
        """Reload settings model from django settings."""
        try:
            self.__settings = self.settings_model.model_validate(_settings)
        except ValueError as ex:
            raise ImproperlyConfigured(str(ex)) from ex

    def __getattr__(self, item: str) -> Any:
        return getattr(self.__settings, item)


class SettingsProxy(SettingsProxyBase[SettingsModel]):
    """Proxy class to access settings from the model.

    This class exists to enable reloading of settings in test cases.
    """

    settings_model = SettingsModel
    __settings: SettingsModel  # pylint: disable=unused-private-member


model_settings = SettingsProxy()
