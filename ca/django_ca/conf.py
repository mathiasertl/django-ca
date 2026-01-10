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
from copy import deepcopy
from datetime import timedelta
from importlib.util import find_spec
from typing import TYPE_CHECKING, Annotated, Any, Generic, Self, TypeVar

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
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from django.conf import settings as _settings
from django.core.exceptions import ImproperlyConfigured
from django.core.signals import setting_changed
from django.utils.translation import gettext_lazy as _

from django_ca import constants
from django_ca.pydantic import NameModel
from django_ca.pydantic.profile import ProfileConfigurationModel
from django_ca.pydantic.type_aliases import (
    AnnotatedEllipticCurveName,
    AnnotatedSignatureHashAlgorithmName,
    CertificateRevocationListReasonCode,
    PowerOfTwoInt,
    Serial,
    UniqueElementsTuple,
)
from django_ca.pydantic.validators import (
    crl_scope_validator,
    dict_env_validator,
    name_oid_parser,
    timedelta_as_number_parser,
)
from django_ca.typehints import ParsableKeyType, SignatureHashAlgorithm

# BeforeValidator currently does not work together with Le(), see:
#   https://github.com/pydantic/pydantic/issues/10459
# TimedeltaAsDays = Annotated[timedelta, BeforeValidator(timedelta_as_number_parser("days"))]
DayValidator = BeforeValidator(timedelta_as_number_parser("days"))
PositiveTimedelta = Annotated[timedelta, Ge(timedelta(days=1))]
AcmeCertValidity = Annotated[PositiveTimedelta, Le(timedelta(days=365)), DayValidator]

_KT = TypeVar("_KT")
_KV = TypeVar("_KV")
DictSetting = Annotated[dict[_KT, _KV], BeforeValidator(dict_env_validator)]

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


class OcspUrlModel(BaseModel):
    """Model for the CA_OCSP_URLS setting."""

    model_config = ConfigDict(from_attributes=True, frozen=True, arbitrary_types_allowed=True)

    ca: str | None = None
    responder_key: str
    responder_cert: x509.Certificate | str
    expires: Annotated[timedelta, Ge(timedelta(seconds=0))] | None = None
    ca_ocsp: bool | None = None


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


class SettingsModel(BaseModel):
    """Pydantic model defining available settings."""

    model_config = ConfigDict(from_attributes=True, frozen=True, arbitrary_types_allowed=True)

    CA_ACME_ORDER_VALIDITY: Annotated[
        timedelta, Ge(timedelta(seconds=60)), Le(timedelta(days=1)), DayValidator
    ] = Field(
        default=timedelta(hours=1),
        description='The time a request for a new certificate ("order") remains valid.',
    )
    CA_ACME_DEFAULT_CERT_VALIDITY: AcmeCertValidity = Field(
        default=timedelta(days=45),
        description="The default validity time any certificate issued via ACME is valid.",
    )
    CA_ACME_MAX_CERT_VALIDITY: AcmeCertValidity = Field(
        default=timedelta(days=90),
        description="The maximum validity time any certificate issued via ACME is valid.",
    )

    CA_CRL_PROFILES: dict[str, CertificateRevocationListProfile] = Field(
        description="A set of CRLs to create using automated tasks. The default value is usually fine.",
        default_factory=lambda: {
            "user": CertificateRevocationListProfile(only_contains_user_certs=True),
            "ca": CertificateRevocationListProfile(only_contains_ca_certs=True),
        },
    )
    CA_DEFAULT_CA: Serial | None = Field(
        default=None, description="The serial of the CA to use when no CA is explicitly given."
    )
    CA_DEFAULT_DSA_SIGNATURE_HASH_ALGORITHM: AnnotatedSignatureHashAlgorithmName = Field(
        default="SHA-256", description="The default signature hash algorithm for new DSA based CAs."
    )
    CA_DEFAULT_ELLIPTIC_CURVE: AnnotatedEllipticCurveName = Field(
        default="secp256r1", description="The default elliptic curve for EC based CAs."
    )
    CA_DEFAULT_EXPIRES: Annotated[PositiveTimedelta, DayValidator] = Field(
        default=timedelta(days=100),
        description="The default validity time for a new certificate.",
    )
    CA_DEFAULT_HOSTNAME: str | None = Field(default=None, examples=["ca.example.com"])
    CA_DEFAULT_KEY_BACKEND: str = Field(
        default="default",
        description="The key backend to use by default. You do not usually have to update this setting.",
    )
    CA_DEFAULT_KEY_SIZE: Annotated[PowerOfTwoInt, Ge(1024)] = Field(
        default=4096,
        description="The default key size for new RSA and DSA based CAs. "
        "Value must be at least ``1024`` and a power of two (e.g. ``2048`` or ``4096``).",
    )
    CA_DEFAULT_NAME_ORDER: UniqueElementsTuple[
        tuple[Annotated[x509.ObjectIdentifier, BeforeValidator(name_oid_parser)], ...]
    ] = (
        NameOID.DN_QUALIFIER,
        NameOID.COUNTRY_NAME,
        NameOID.POSTAL_CODE,
        NameOID.STATE_OR_PROVINCE_NAME,
        NameOID.LOCALITY_NAME,
        NameOID.DOMAIN_COMPONENT,
        NameOID.ORGANIZATION_NAME,
        NameOID.ORGANIZATIONAL_UNIT_NAME,
        NameOID.TITLE,
        NameOID.COMMON_NAME,
        NameOID.USER_ID,
        NameOID.EMAIL_ADDRESS,
        NameOID.SERIAL_NUMBER,
    )
    CA_DEFAULT_OCSP_KEY_BACKEND: str = "default"
    CA_DEFAULT_PRIVATE_KEY_TYPE: ParsableKeyType = Field(
        default="RSA", description="The default key type for new CAs."
    )
    CA_DEFAULT_PROFILE: str = Field(
        default="webserver", description="The default :doc:`profile </profiles>` to use."
    )
    CA_DEFAULT_SIGNATURE_HASH_ALGORITHM: AnnotatedSignatureHashAlgorithmName = Field(
        default="SHA-512", description="The default signature hash algorithm for new RSA and EC based CAs."
    )
    CA_DEFAULT_STORAGE_ALIAS: str = Field(
        default="django-ca",
        description="",
    )
    CA_DEFAULT_SUBJECT: NameModel | None = Field(
        default=None,
        examples=[
            [
                {"oid": "countryName", "value": "AT"},
                {"oid": "localityName", "value": "Vienna"},
                {"oid": "organizationName", "value": "django-ca"},
            ],
            [
                {"oid": "C", "value": "AT"},
                {"oid": "localityName", "value": "Vienna"},
                {"oid": NameOID.ORGANIZATION_NAME.dotted_string, "value": "django-ca"},
            ],
        ],
    )
    CA_ENABLE_ACME: bool = Field(
        default=True, description="Set to ``False`` to disable all ACME functionality."
    )
    CA_ENABLE_REST_API: bool = False
    CA_KEY_BACKENDS: dict[str, KeyBackendConfigurationModel] = Field(default_factory=dict)
    CA_MIN_KEY_SIZE: Annotated[PowerOfTwoInt, Ge(1024)] = Field(
        default=2048,
        description="The minimum key size for new CAs (not used for CAs based on EC, Ed448 or Ed25519).",
    )
    CA_NOTIFICATION_DAYS: tuple[int, ...] = Field(
        default=(14, 7, 3, 1),
        description="Days before expiry that certificate watchers will receive notifications.",
    )
    CA_OCSP_KEY_BACKENDS: dict[str, KeyBackendConfigurationModel] = Field(default_factory=dict)

    # The minimum value comes from the fact that the renewal task only runs every hour by default.
    CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL: Annotated[timedelta, Ge(timedelta(hours=2))] = Field(
        default=timedelta(days=1),
        description="Renew OCSP certificates if they expire within the given interval.",
    )
    CA_OCSP_URLS: dict[str, OcspUrlModel] = Field(
        default_factory=dict,
        description="Configuration for OCSP responders. See :doc:`/ocsp` for more information.",
        examples=[
            {
                "path-name": OcspUrlModel(
                    ca="ca-name-or-serial",
                    responder_key="-----BEGIN PRIVATE KEY-----\n...",
                    responder_cert="-----BEGIN CERTIFICATE-----\n...",
                    expires=timedelta(days=1),
                    ca_ocsp=False,
                )
            }
        ],
    )

    CA_PASSWORDS: dict[Serial, bytes] = Field(
        default_factory=dict,
        description="Passwords for encrypted private keys of certificate authorities.",
        examples=[{"example-serial": "example-secret-password"}],
    )
    CA_PROFILES: DictSetting[str, ProfileConfigurationModel] = Field(
        default_factory=lambda: {
            k: ProfileConfigurationModel(**v) for k, v in deepcopy(_DEFAULT_CA_PROFILES).items()
        },
        json_schema_extra={"default_explanation": "See :doc:`/profiles`."},
    )
    CA_USE_CELERY: bool = Field(
        default_factory=lambda: find_spec("celery") is not None,
        description="If `Celery <https://docs.celeryproject.org>`_ is used for asynchronous tasks or not.",
        json_schema_extra={"default_explanation": "``True`` if Celery is installed, ``False`` if not."},
    )

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
            self.CA_OCSP_KEY_BACKENDS["db"] = KeyBackendConfigurationModel(
                BACKEND="django_ca.key_backends.db.ocsp_backend.DBOCSPBackend",
                OPTIONS={},
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

    @model_validator(mode="after")
    def validate_acme_cert_validity(self) -> Self:
        """Validate that ``CA_ACME_MAX_CERT_VALIDITY`` is >= ``CA_ACME_DEFAULT_CERT_VALIDITY``."""
        if self.CA_ACME_MAX_CERT_VALIDITY < self.CA_ACME_DEFAULT_CERT_VALIDITY:
            raise ValueError("CA_ACME_DEFAULT_CERT_VALIDITY is greater then CA_ACME_MAX_CERT_VALIDITY.")
        return self

    def get_default_signature_hash_algorithm(self) -> SignatureHashAlgorithm:
        """Get the |HashAlgorithm| instance for this model."""
        return constants.SIGNATURE_HASH_ALGORITHM_TYPES[self.CA_DEFAULT_SIGNATURE_HASH_ALGORITHM]()

    def get_default_dsa_signature_hash_algorithm(self) -> SignatureHashAlgorithm:
        """Get the |HashAlgorithm| instance for this model."""
        return constants.SIGNATURE_HASH_ALGORITHM_TYPES[self.CA_DEFAULT_DSA_SIGNATURE_HASH_ALGORITHM]()

    def get_default_elliptic_curve(self) -> ec.EllipticCurve:
        """Get the |EllipticCurve| instance for this model."""
        return constants.ELLIPTIC_CURVE_TYPES[self.CA_DEFAULT_ELLIPTIC_CURVE]()


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
    __settings__: BaseModelTypeVar

    def __init__(self, reload_on_change: bool = True) -> None:
        self.reload()

        # Connect signal handler to reload the underlying Pydantic model when settings change.
        if reload_on_change is True:  # pragma: no branch
            self._connect_settings_changed()

    def __dir__(self, object: Any = None) -> Iterable[str]:  # pylint: disable=redefined-builtin
        # Used by ipython for tab completion, see:
        #   http://ipython.org/ipython-doc/dev/config/integrating.html
        getters = [getter for getter in dir(self.settings_model) if getter.startswith("get_")]
        return list(super().__dir__()) + list(self.settings_model.model_fields) + getters

    def _connect_settings_changed(self) -> None:
        setting_changed.connect(self._reload_from_signal)

    def _reload_from_signal(self, **kwargs: Any) -> None:
        self.reload()

    def reload(self) -> None:
        """Reload settings model from django settings."""
        try:
            self.__settings__ = self.settings_model.model_validate(_settings)
        except ValueError as ex:
            raise ImproperlyConfigured(str(ex)) from ex

    def __getattr__(self, item: str) -> Any:
        return getattr(self.__settings__, item)


class SettingsProxy(SettingsProxyBase[SettingsModel]):
    """Proxy class to access settings from the model.

    This class exists to enable reloading of settings in test cases.
    """

    settings_model = SettingsModel
    __settings__: SettingsModel

    if TYPE_CHECKING:
        # pylint: disable=missing-function-docstring
        # Our custom mypy plugin currently does not proxy getter methods, as I couldn't get this to
        # work properly. We thus add some typehints here so that mypy (and PyCharm) finds these methods.
        def get_default_signature_hash_algorithm(self) -> SignatureHashAlgorithm: ...

        def get_default_dsa_signature_hash_algorithm(self) -> SignatureHashAlgorithm: ...

        def get_default_elliptic_curve(self) -> ec.EllipticCurve: ...


model_settings = SettingsProxy()
