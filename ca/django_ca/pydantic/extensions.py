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

"""Pydantic models for x509 extensions.

Every extension model has exactly three parameters, `critical`, `value` and `type`.

The `critical` parameter is a boolean value. It usually defaults to the recommended value (usually in
`RFC 5280`_), but is mandatory in some extensions where no value is defined. Default values are defined in
:py:attr:`~django_ca.constants.EXTENSION_DEFAULT_CRITICAL`.

The `value` parameter represents the actual value of the extension, and its format is different for every
extension. In trivial extensions (for example in the
:py:class:`~django_ca.pydantic.extensions.InhibitAnyPolicyModel`), this is usually a basic type:

    >>> InhibitAnyPolicyModel(value=1)
    InhibitAnyPolicyModel(critical=True, value=1)

More complex extensions require a nested model:

    >>> dpoint = DistributionPointModel(
    ...     full_name=[{"type": "URI", "value": "https://ca.example.com/crl"}]
    ... )
    >>> CRLDistributionPointsModel(value=[dpoint])  # doctest: +STRIP_WHITESPACE
    CRLDistributionPointsModel(
        critical=False,
        value=[DistributionPointModel(
            full_name=[GeneralNameModel(type='URI', value='https://ca.example.com/crl')],
            relative_name=None, crl_issuer=None, reasons=None
        )]
    )

Nested models are described in more details under :ref:`pydantic_extension_attributes`.

Every model has a `cryptography` property returning the |Extension| instance and an `extension_type` property
returning the |ExtensionType| instance:

    >>> ext_model = InhibitAnyPolicyModel(value=1)
    >>> ext_model.extension_type
    <InhibitAnyPolicy(skip_certs=1)>
    >>> ext_model.cryptography  # doctest: +STRIP_WHITESPACE
    <Extension(
        oid=<ObjectIdentifier(oid=2.5.29.54, name=inhibitAnyPolicy)>,
        critical=True,
        value=<InhibitAnyPolicy(skip_certs=1)>
    )>

Finally, the `type` parameter is a literal string used to identify the type of extension. It is mandatory in
serialized versions of a model (e.g. as JSON), but does not have to be given when instantiating a model
directly.
"""

import abc
import base64
from types import MappingProxyType
from typing import (  # noqa: UP035  # see typing.Type usage below
    TYPE_CHECKING,
    Annotated,
    Any,
    ClassVar,
    Literal,
    NoReturn,
    Optional,
    Type,
    TypeVar,
    Union,
    cast,
)

from pydantic import (
    AfterValidator,
    Base64Bytes,
    BeforeValidator,
    ConfigDict,
    Field,
    TypeAdapter,
    field_validator,
    model_validator,
)
from pydantic.fields import ModelPrivateAttr
from pydantic_core.core_schema import ValidationInfo

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, SubjectInformationAccessOID

from django_ca.constants import EXTENSION_DEFAULT_CRITICAL, KEY_USAGE_NAMES
from django_ca.pydantic import validators
from django_ca.pydantic.base import CryptographyModel
from django_ca.pydantic.extension_attributes import (
    AccessDescriptionModel,
    AuthorityKeyIdentifierValueModel,
    BasicConstraintsValueModel,
    DistributionPointModel,
    IssuingDistributionPointValueModel,
    MSCertificateTemplateValueModel,
    NameConstraintsValueModel,
    PolicyConstraintsValueModel,
    PolicyInformationModel,
    SignedCertificateTimestampModel,
    UnrecognizedExtensionValueModel,
)
from django_ca.pydantic.general_name import GeneralNameModel
from django_ca.pydantic.type_aliases import NonEmptyOrderedSet
from django_ca.typehints import (
    AlternativeNameTypeVar,
    CRLExtensionTypeTypeVar,
    ExtensionTypeTypeVar,
    InformationAccessTypeVar,
    KeyUsages,
    NoValueExtensionTypeVar,
    SerializedPydanticExtension,
    SignedCertificateTimestampTypeVar,
)

if TYPE_CHECKING:
    from typing import Self

    from pydantic.main import IncEx

###############
# Base models #
###############


class ExtensionModel(CryptographyModel[ExtensionTypeTypeVar], metaclass=abc.ABCMeta):
    """Base class for all extension models."""

    type: str = Field(repr=False)
    critical: bool
    value: Any
    requires_critical: ClassVar[Optional[bool]] = None

    @field_validator("critical", mode="after")
    @classmethod
    def validate_critical(cls, critical: bool, info: ValidationInfo) -> bool:
        """Validate that the critical flag is correct if the defining RFC mandates a value."""
        if info.context is not None and info.context.get("validate_required_critical", True) is False:
            return critical

        if cls.requires_critical is True and cls.requires_critical != critical:
            raise ValueError("this extension must be marked as critical")
        if cls.requires_critical is False and cls.requires_critical != critical:
            raise ValueError("this extension must be marked as non-critical")
        return critical

    @property
    def cryptography(self) -> x509.Extension[ExtensionTypeTypeVar]:  # type: ignore[override]
        """Convert to a :py:class:`~cg:cryptography.x509.Extension` instance."""
        value = self.extension_type
        return x509.Extension(oid=value.oid, critical=self.critical, value=value)

    @property
    @abc.abstractmethod
    def extension_type(self) -> ExtensionTypeTypeVar:
        """ExtensionType subclass for this extension."""

    if TYPE_CHECKING:
        # pylint: disable=unused-argument,missing-function-docstring

        def model_dump(  # type: ignore[override]
            self,
            *,
            mode: Literal["json", "python"] | str = "python",
            include: IncEx = None,
            exclude: IncEx = None,
            by_alias: bool = False,
            exclude_unset: bool = False,
            exclude_defaults: bool = False,
            exclude_none: bool = False,
            round_trip: bool = False,
            warnings: bool = True,
        ) -> SerializedPydanticExtension: ...


class BaseExtensionModel(ExtensionModel[ExtensionTypeTypeVar], metaclass=abc.ABCMeta):
    """Abstract base class for extension base classes.

    This base class adds the ``_extension_type`` attribute and the ``get_extension_type_class`` classmethod.
    """

    _extension_type: type[ExtensionTypeTypeVar]

    # TYPEHINT NOTE: mypy complains when using type instead of Type.
    @classmethod
    def get_extension_type_class(cls) -> Type[ExtensionTypeTypeVar]:  # noqa: UP006
        """Get the :py:class:`~cg:cryptography.x509.ExtensionType` class configured via ``_extension_type``.

        Pydantic models will have a ``ModelPrivateAttr`` in class methods, instead of the actual configured
        class. The "good" solution would be to configure ``_extension_type`` as ``ClassVar``, but MyPy
        currently forbids this:

            https://github.com/python/mypy/issues/5144
        """
        private_attr = cast(ModelPrivateAttr, cls._extension_type)
        return private_attr.default  # type: ignore[no-any-return]


class NoValueExtensionModel(BaseExtensionModel[NoValueExtensionTypeVar]):
    """Base model for extensions that do not have a value."""

    _extension_type: type[NoValueExtensionTypeVar]
    value: None = Field(default=None, repr=False)

    @model_validator(mode="before")
    @classmethod
    def parse_cryptography(cls, data: Any) -> Any:
        """Parse cryptography instances."""
        extension_type_class = cls.get_extension_type_class()
        if isinstance(data, x509.Extension) and isinstance(data.value, extension_type_class):
            return {"critical": data.critical}
        return data

    @property
    def extension_type(self) -> NoValueExtensionTypeVar:
        """Convert to the respective cryptography extension type instance."""
        return self._extension_type()


class AlternativeNameBaseModel(BaseExtensionModel[AlternativeNameTypeVar]):
    """Base model for extensions with a list of general names as value."""

    _extension_type: type[AlternativeNameTypeVar]

    value: NonEmptyOrderedSet[list[GeneralNameModel]]

    @model_validator(mode="before")
    @classmethod
    def parse_cryptography(cls, data: Any) -> Any:
        """Parse cryptography instances."""
        extension_type_class = cls.get_extension_type_class()
        if isinstance(data, x509.Extension) and isinstance(data.value, extension_type_class):
            return {"critical": data.critical, "value": list(data.value)}
        return data

    @property
    def extension_type(self) -> AlternativeNameTypeVar:
        """Convert to the respective cryptography extension type instance."""
        return self._extension_type(general_names=[name.cryptography for name in self.value])


class CRLExtensionBaseModel(BaseExtensionModel[CRLExtensionTypeTypeVar]):
    """Base model for extensions with a list of distribution points."""

    _extension_type: type[CRLExtensionTypeTypeVar]

    value: NonEmptyOrderedSet[list[DistributionPointModel]]

    @model_validator(mode="before")
    @classmethod
    def parse_cryptography(cls, data: Any) -> Any:
        """Parse cryptography instances."""
        extension_type_class = cls.get_extension_type_class()
        if isinstance(data, x509.Extension) and isinstance(data.value, extension_type_class):
            return {"critical": data.critical, "value": list(data.value)}
        return data

    @property
    def extension_type(self) -> CRLExtensionTypeTypeVar:
        """Convert to the respective cryptography extension instance."""
        return self._extension_type(distribution_points=[dpoint.cryptography for dpoint in self.value])


class InformationAccessBaseModel(BaseExtensionModel[InformationAccessTypeVar]):
    """Base model for extensions with a list of access descriptions."""

    _extension_type: type[InformationAccessTypeVar]
    _acceptable_oids: ClassVar[tuple[str, ...]]

    value: NonEmptyOrderedSet[list[AccessDescriptionModel]]

    @model_validator(mode="before")
    @classmethod
    def parse_cryptography(cls, data: Any) -> Any:
        """Parse cryptography instances."""
        extension_type_class = cls.get_extension_type_class()
        if isinstance(data, x509.Extension) and isinstance(data.value, extension_type_class):
            return {"critical": data.critical, "value": list(data.value)}
        return data

    @model_validator(mode="after")
    # pylint: disable-next=missing-function-docstring
    def check_consistency(self) -> "Self":
        for desc in self.value:
            if desc.access_method not in self._acceptable_oids:
                raise ValueError(f"{desc.access_method}: access_method not acceptable for this extension.")
        return self

    @property
    def extension_type(self) -> InformationAccessTypeVar:
        """Convert to the respective cryptography extension instance."""
        return self._extension_type(descriptions=[ad.cryptography for ad in self.value])


class SignedCertificateTimestampBaseModel(ExtensionModel[SignedCertificateTimestampTypeVar]):
    """Base class for a extensions with a list of signed certificate timestamps."""

    model_config = ConfigDict(from_attributes=True)
    _extension_type: type[SignedCertificateTimestampTypeVar]

    value: NonEmptyOrderedSet[list[SignedCertificateTimestampModel]]

    @property
    def extension_type(self) -> NoReturn:  # pragma: no cover
        """Convert to the respective cryptography extension instance."""
        raise ValueError(f"{self._extension_type.__name__} cannot be loaded as cryptography instances.")


########################
# ExtensionType models #
########################


class AuthorityInformationAccessModel(InformationAccessBaseModel[x509.AuthorityInformationAccess]):
    """Pydantic model for a :py:class:`~cg:cryptography.x509.AuthorityInformationAccess` extension.

    The `value` is a list of :py:class:`~django_ca.pydantic.extension_attributes.AccessDescriptionModel`
    instances:

    >>> ocsp = AccessDescriptionModel(
    ...     access_method='ocsp',
    ...     access_location={'type': 'URI', 'value': 'http://ocsp.example.com'}
    ... )
    >>> issuers = AccessDescriptionModel(
    ...     access_method='ca_issuers',
    ...     access_location={'type': 'URI', 'value': 'http://example.com'}
    ... )
    >>> AuthorityInformationAccessModel(value=[ocsp, issuers])  # doctest: +STRIP_WHITESPACE
    AuthorityInformationAccessModel(
        critical=False,
        value=[
            AccessDescriptionModel(
                access_method='1.3.6.1.5.5.7.48.1',
                access_location=GeneralNameModel(type='URI', value='http://ocsp.example.com')
            ),
            AccessDescriptionModel(
                access_method='1.3.6.1.5.5.7.48.2',
                access_location=GeneralNameModel(type='URI', value='http://example.com')
            )
        ]
    )
    """

    _extension_type = x509.AuthorityInformationAccess
    _acceptable_oids = (
        AuthorityInformationAccessOID.OCSP.dotted_string,
        AuthorityInformationAccessOID.CA_ISSUERS.dotted_string,
    )
    type: Literal["authority_information_access"] = Field(default="authority_information_access", repr=False)
    critical: bool = EXTENSION_DEFAULT_CRITICAL[ExtensionOID.AUTHORITY_INFORMATION_ACCESS]
    requires_critical: ClassVar[bool] = False  # MUST mark this extension as non-critical.


class AuthorityKeyIdentifierModel(ExtensionModel[x509.AuthorityKeyIdentifier]):
    """Pydantic model for a :py:class:`~cg:cryptography.x509.AuthorityKeyIdentifier` extension.

    The `value` is a :py:class:`~django_ca.pydantic.extension_attributes.AuthorityKeyIdentifierValueModel`
    instance:

    >>> value = AuthorityKeyIdentifierValueModel(key_identifier=b"MTIz")
    >>> AuthorityKeyIdentifierModel(value=value)  # doctest: +STRIP_WHITESPACE
    AuthorityKeyIdentifierModel(
        critical=False,
        value=AuthorityKeyIdentifierValueModel(
            key_identifier=b'123', authority_cert_issuer=None, authority_cert_serial_number=None
        )
    )
    """

    model_config = ConfigDict(from_attributes=True)
    type: Literal["authority_key_identifier"] = Field(default="authority_key_identifier", repr=False)
    critical: bool = EXTENSION_DEFAULT_CRITICAL[ExtensionOID.AUTHORITY_KEY_IDENTIFIER]
    value: AuthorityKeyIdentifierValueModel
    requires_critical: ClassVar[bool] = False  # MUST mark this extension as non-critical.

    @property
    def extension_type(self) -> x509.AuthorityKeyIdentifier:
        """Convert to a :py:class:`~cg:cryptography.x509.AuthorityKeyIdentifier` instance."""
        return self.value.cryptography


class BasicConstraintsModel(ExtensionModel[x509.BasicConstraints]):
    """Pydantic model for a :py:class:`~cg:cryptography.x509.BasicConstraints` extension.

    The `value` is a :py:class:`~django_ca.pydantic.extension_attributes.BasicConstraintsValueModel`
    instance. For example, for a certificate authority:

    >>> value = BasicConstraintsValueModel(ca=True, path_length=0)
    >>> BasicConstraintsModel(value=value)
    BasicConstraintsModel(critical=True, value=BasicConstraintsValueModel(ca=True, path_length=0))

    For end-entity certificates, sets `ca` to ``False`` and `path_length` to ``None``:

    >>> value = BasicConstraintsValueModel(ca=False, path_length=None)
    >>> BasicConstraintsModel(value=value)
    BasicConstraintsModel(critical=True, value=BasicConstraintsValueModel(ca=False, path_length=None))
    """

    model_config = ConfigDict(from_attributes=True)
    type: Literal["basic_constraints"] = Field(default="basic_constraints", repr=False)
    critical: bool = EXTENSION_DEFAULT_CRITICAL[ExtensionOID.BASIC_CONSTRAINTS]
    value: BasicConstraintsValueModel

    @property
    def extension_type(self) -> x509.BasicConstraints:
        """Convert to a :py:class:`~cg:cryptography.x509.BasicConstraints` instance."""
        return self.value.cryptography


class CRLDistributionPointsModel(CRLExtensionBaseModel[x509.CRLDistributionPoints]):
    """Pydantic model for a :py:class:`~cg:cryptography.x509.CRLDistributionPoints` extension.

    The `value` is a list of :py:class:`~django_ca.pydantic.extension_attributes.DistributionPointModel`
    instances:

    >>> dpoint = DistributionPointModel(
    ...     full_name=[{"type": "URI", "value": "https://ca.example.com/crl"}]
    ... )
    >>> CRLDistributionPointsModel(value=[dpoint])  # doctest: +STRIP_WHITESPACE
    CRLDistributionPointsModel(
        critical=False,
        value=[DistributionPointModel(
            full_name=[GeneralNameModel(type='URI', value='https://ca.example.com/crl')],
            relative_name=None, crl_issuer=None, reasons=None
        )]
    )

    Please refer to the ``DistributionPointModel`` documentation for full information on how to instantiate
    this model.
    """

    _extension_type = x509.CRLDistributionPoints
    type: Literal["crl_distribution_points"] = Field(default="crl_distribution_points", repr=False)
    critical: bool = EXTENSION_DEFAULT_CRITICAL[ExtensionOID.CRL_DISTRIBUTION_POINTS]


class CRLNumberModel(ExtensionModel[x509.CRLNumber]):
    """Pydantic model for a :py:class:`~cg:cryptography.x509.CRLNumber` extension.

    The `value` is an integer:

    >>> CRLNumberModel(value=1)
    CRLNumberModel(critical=False, value=1)
    """

    type: Literal["crl_number"] = Field(default="crl_number", repr=False)
    critical: bool = EXTENSION_DEFAULT_CRITICAL[ExtensionOID.CRL_NUMBER]
    requires_critical: ClassVar[bool] = False  # is a non-critical CRL extension

    value: int = Field(ge=0)

    @model_validator(mode="before")
    @classmethod
    def parse_cryptography(cls, data: Any) -> Any:
        """Parse cryptography instances."""
        if isinstance(data, x509.Extension) and isinstance(data.value, x509.CRLNumber):
            return {"critical": data.critical, "value": data.value.crl_number}
        return data

    @property
    def extension_type(self) -> x509.CRLNumber:
        """Convert to a :py:class:`~cg:cryptography.x509.CRLNumber` instance."""
        return x509.CRLNumber(crl_number=self.value)


class CertificatePoliciesModel(ExtensionModel[x509.CertificatePolicies]):
    """Pydantic model for a :py:class:`~cg:cryptography.x509.CertificatePolicies` extension.

    The `value` is a list of :py:class:`~django_ca.pydantic.extension_attributes.PolicyInformationModel`
    instances:

    >>> policy = PolicyInformationModel(policy_identifier="2.5.29.32.0")
    >>> CertificatePoliciesModel(value=[policy])  # doctest: +STRIP_WHITESPACE
    CertificatePoliciesModel(
        critical=False,
        value=[
            PolicyInformationModel(policy_identifier='2.5.29.32.0', policy_qualifiers=None)
        ]
    )
    """

    model_config = ConfigDict(json_schema_extra={"description": "A CertificatePolicies extension."})

    type: Literal["certificate_policies"] = Field(default="certificate_policies", repr=False)
    critical: bool = EXTENSION_DEFAULT_CRITICAL[ExtensionOID.CERTIFICATE_POLICIES]

    value: NonEmptyOrderedSet[list[PolicyInformationModel]] = Field(
        description="The value of the CertificatePolicies extension is a list of policy information objects.",
        json_schema_extra={"minItems": 1, "uniqueItems": True},
    )

    @model_validator(mode="before")
    @classmethod
    def parse_cryptography(cls, data: Any) -> Any:
        """Parse cryptography instances."""
        if isinstance(data, x509.Extension) and isinstance(data.value, x509.CertificatePolicies):
            return {"critical": data.critical, "value": list(data.value)}
        return data

    @property
    def extension_type(self) -> x509.CertificatePolicies:
        """Convert to a :py:class:`~cg:cryptography.x509.CertificatePolicies` instance."""
        return x509.CertificatePolicies([pol.cryptography for pol in self.value])


class DeltaCRLIndicatorModel(ExtensionModel[x509.DeltaCRLIndicator]):
    """Pydantic model for a :py:class:`~cg:cryptography.x509.DeltaCRLIndicator` extension.

    The `value` is an integer:

    >>> DeltaCRLIndicatorModel(value=1)
    DeltaCRLIndicatorModel(critical=True, value=1)
    """

    type: Literal["delta_crl_indicator"] = Field(default="delta_crl_indicator", repr=False)
    critical: bool = EXTENSION_DEFAULT_CRITICAL[ExtensionOID.DELTA_CRL_INDICATOR]
    requires_critical: ClassVar[bool] = True  # is a critical CRL extension

    value: int = Field(ge=0)

    @model_validator(mode="before")
    @classmethod
    def parse_cryptography(cls, data: Any) -> Any:
        """Parse cryptography instances."""
        if isinstance(data, x509.Extension) and isinstance(data.value, x509.DeltaCRLIndicator):
            return {"critical": data.critical, "value": data.value.crl_number}
        return data

    @property
    def extension_type(self) -> x509.DeltaCRLIndicator:
        """Convert to a :py:class:`~cg:cryptography.x509.DeltaCRLIndicator` instance."""
        return x509.DeltaCRLIndicator(crl_number=self.value)


class ExtendedKeyUsageModel(ExtensionModel[x509.ExtendedKeyUsage]):
    """Pydantic model for a :py:class:`~cg:cryptography.x509.ExtendedKeyUsage` extension.

    The `value` is a list valid object identifiers as dotted strings. For convenience, any name from
    :py:attr:`~django_ca.constants.EXTENDED_KEY_USAGE_NAMES` can also be given:

    >>> ExtendedKeyUsageModel(value=["clientAuth", "1.3.6.1.5.5.7.3.1"])
    ExtendedKeyUsageModel(critical=False, value=['1.3.6.1.5.5.7.3.2', '1.3.6.1.5.5.7.3.1'])
    """

    type: Literal["extended_key_usage"] = Field(default="extended_key_usage", repr=False)
    critical: bool = EXTENSION_DEFAULT_CRITICAL[ExtensionOID.EXTENDED_KEY_USAGE]
    value: NonEmptyOrderedSet[
        list[
            Annotated[
                str,
                BeforeValidator(validators.oid_parser),
                AfterValidator(validators.extended_key_usage_validator),
                AfterValidator(validators.oid_validator),
            ]
        ]
    ]

    @model_validator(mode="before")
    @classmethod
    def parse_cryptography(cls, data: Any) -> Any:
        """Parse cryptography instances."""
        if isinstance(data, x509.Extension) and isinstance(data.value, x509.ExtendedKeyUsage):
            return {"critical": data.critical, "value": list(data.value)}
        return data

    @property
    def extension_type(self) -> x509.ExtendedKeyUsage:
        """Convert to a :py:class:`~cg:cryptography.x509.ExtendedKeyUsage` instance."""
        return x509.ExtendedKeyUsage(usages=[x509.ObjectIdentifier(usage) for usage in self.value])


class FreshestCRLModel(CRLExtensionBaseModel[x509.FreshestCRL]):
    """Pydantic model for a :py:class:`~cg:cryptography.x509.FreshestCRL` extension.

    This model behaves exactly like :py:class:`~django_ca.pydantic.extensions.CRLDistributionPointsModel`.
    """

    _extension_type = x509.FreshestCRL
    type: Literal["freshest_crl"] = Field(default="freshest_crl", repr=False)
    critical: bool = EXTENSION_DEFAULT_CRITICAL[ExtensionOID.FRESHEST_CRL]
    requires_critical: ClassVar[bool] = False  # MUST be marked as non-critical


class InhibitAnyPolicyModel(ExtensionModel[x509.InhibitAnyPolicy]):
    """Pydantic model for a :py:class:`~cg:cryptography.x509.InhibitAnyPolicy` extension.

    The `value` attribute is an integer:

    >>> InhibitAnyPolicyModel(value=1)
    InhibitAnyPolicyModel(critical=True, value=1)
    """

    type: Literal["inhibit_any_policy"] = Field(default="inhibit_any_policy", repr=False)
    critical: bool = EXTENSION_DEFAULT_CRITICAL[ExtensionOID.INHIBIT_ANY_POLICY]
    value: int = Field(ge=0)
    requires_critical: ClassVar[bool] = True  # MUST mark this extension as critical

    @model_validator(mode="before")
    @classmethod
    def parse_cryptography(cls, data: Any) -> Any:
        """Parse cryptography instances."""
        if isinstance(data, x509.Extension) and isinstance(data.value, x509.InhibitAnyPolicy):
            return {"critical": data.critical, "value": data.value.skip_certs}

        return data

    @property
    def extension_type(self) -> x509.InhibitAnyPolicy:
        """Convert to a :py:class:`~cg:cryptography.x509.InhibitAnyPolicy` instance."""
        return x509.InhibitAnyPolicy(skip_certs=self.value)


class IssuerAlternativeNameModel(AlternativeNameBaseModel[x509.IssuerAlternativeName]):
    """Pydantic model for a :py:class:`~cg:cryptography.x509.IssuerAlternativeName` extension.

    This model behaves exactly like :py:class:`~django_ca.pydantic.extensions.SubjectAlternativeNameModel`.
    """

    _extension_type = x509.IssuerAlternativeName
    type: Literal["issuer_alternative_name"] = Field(default="issuer_alternative_name", repr=False)
    critical: bool = EXTENSION_DEFAULT_CRITICAL[ExtensionOID.ISSUER_ALTERNATIVE_NAME]


class IssuingDistributionPointModel(ExtensionModel[x509.IssuingDistributionPoint]):
    """Pydantic model for a :py:class:`~cg:cryptography.x509.IssuingDistributionPoint` extension.

    The `value` is a :py:class:`~django_ca.pydantic.extension_attributes.IssuingDistributionPointValueModel`
    instances:

    >>> full_name = [{"type": "URI", "value": "https://ca.example.com/crl"}]
    >>> value = IssuingDistributionPointValueModel(full_name=full_name)
    >>> IssuingDistributionPointModel(value=value)  # doctest: +ELLIPSIS
    IssuingDistributionPointModel(critical=True, value=IssuingDistributionPointValueModel(...))
    """

    model_config = ConfigDict(from_attributes=True)

    type: Literal["issuing_distribution_point"] = Field(default="issuing_distribution_point", repr=False)
    critical: bool = EXTENSION_DEFAULT_CRITICAL[ExtensionOID.ISSUING_DISTRIBUTION_POINT]
    value: IssuingDistributionPointValueModel
    requires_critical: ClassVar[bool] = True  # "is a critical CRL extension"

    @property
    def extension_type(self) -> x509.IssuingDistributionPoint:
        """Convert to a :py:class:`~cg:cryptography.x509.IssuingDistributionPoint` instance."""
        return self.value.cryptography


class KeyUsageModel(ExtensionModel[x509.KeyUsage]):
    """Pydantic model for a :py:class:`~cg:cryptography.x509.KeyUsage` extension.

    All key usages default to ``False``, so you can skip giving any usages you don't care about:

    >>> KeyUsageModel(value=["key_agreement", "key_encipherment"])
    KeyUsageModel(critical=True, value=['key_agreement', 'key_encipherment'])

    For convenience, the model also accepts values as used in `RFC 5280`_ (full mapping in
    :py:attr:`~django_ca.constants.KEY_USAGE_NAMES`):

    >>> KeyUsageModel(value=["keyAgreement", "keyEncipherment"])
    KeyUsageModel(critical=True, value=['key_agreement', 'key_encipherment'])
    """

    type: Literal["key_usage"] = Field(default="key_usage", repr=False)
    critical: bool = EXTENSION_DEFAULT_CRITICAL[ExtensionOID.KEY_USAGE]
    value: NonEmptyOrderedSet[
        list[Annotated[Literal[KeyUsages], BeforeValidator(validators.key_usage_validator)]]
    ]

    @model_validator(mode="before")
    @classmethod
    def parse_cryptography(cls, data: Any) -> Any:
        """Parse cryptography instances."""
        if isinstance(data, x509.Extension) and isinstance(data.value, x509.KeyUsage):
            extension_type: x509.KeyUsage = data.value
            values: list[Literal[KeyUsages]] = []
            for value in KEY_USAGE_NAMES:
                try:
                    if getattr(extension_type, value) is True:
                        values.append(value)
                except ValueError:
                    # encipher_only and decipher_only throw ValueError if key_agreement is False
                    pass

            return {"critical": data.critical, "value": values}
        return data

    @model_validator(mode="after")
    # pylint: disable-next=missing-function-docstring
    def check_key_agreement(self) -> "KeyUsageModel":
        if "key_agreement" not in self.value and (
            "encipher_only" in self.value or "decipher_only" in self.value
        ):
            raise ValueError("encipher_only and decipher_only can only be set when key_agreement is set")
        return self

    @property
    def extension_type(self) -> x509.KeyUsage:
        """Convert to a :py:class:`~cg:cryptography.x509.KeyUsage` instance."""
        params: dict[str, bool] = {k: k in self.value for k in KEY_USAGE_NAMES}
        return x509.KeyUsage(**params)


class MSCertificateTemplateModel(ExtensionModel[x509.MSCertificateTemplate]):
    """Pydantic model for a :py:class:`~cg:cryptography.x509.MSCertificateTemplate` extension.

    The `value` is a :py:class:`~django_ca.pydantic.extension_attributes.MSCertificateTemplateValueModel`
    instance:

    >>> value = MSCertificateTemplateValueModel(template_id="1.2.3", major_version=1)
    >>> MSCertificateTemplateModel(critical=True, value=value)  # doctest: +STRIP_WHITESPACE
    MSCertificateTemplateModel(
        critical=True,
        value=MSCertificateTemplateValueModel(template_id='1.2.3', major_version=1, minor_version=None)
    )

    Note that this extension does not have a default defined for the `critical` parameter, so it is mandatory.
    """

    model_config = ConfigDict(from_attributes=True)
    type: Literal["ms_certificate_template"] = Field(default="ms_certificate_template", repr=False)
    critical: bool
    value: MSCertificateTemplateValueModel

    @property
    def extension_type(self) -> x509.MSCertificateTemplate:
        """Convert to a :py:class:`~cg:cryptography.x509.MSCertificateTemplate` instance."""
        return self.value.cryptography


class NameConstraintsModel(ExtensionModel[x509.NameConstraints]):
    """Pydantic model for a :py:class:`~cg:cryptography.x509.NameConstraints` extension.

    The `value` is a :py:class:`~django_ca.pydantic.extension_attributes.NameConstraintsValueModel` instance:

    >>> value = NameConstraintsValueModel(permitted_subtrees=[{"type": "DNS", "value": ".com"}])
    >>> NameConstraintsModel(value=value) # doctest: +STRIP_WHITESPACE
    NameConstraintsModel(
        critical=True,
        value=NameConstraintsValueModel(
            permitted_subtrees=[GeneralNameModel(type='DNS', value='.com')],
            excluded_subtrees=None
        )
    )
    """

    model_config = ConfigDict(from_attributes=True)
    type: Literal["name_constraints"] = Field(default="name_constraints", repr=False)
    critical: bool = EXTENSION_DEFAULT_CRITICAL[ExtensionOID.NAME_CONSTRAINTS]
    value: NameConstraintsValueModel
    requires_critical: ClassVar[bool] = True  # MUST mark this extension as critical

    @property
    def extension_type(self) -> x509.NameConstraints:
        """The :py:class:`~cg:cryptography.x509.NameConstraints` instance."""
        return self.value.cryptography


class OCSPNoCheckModel(NoValueExtensionModel[x509.OCSPNoCheck]):
    """Pydantic model for a :py:class:`~cg:cryptography.x509.OCSPNoCheck` extension.

    This extension does not have a value, and thus can be instantiated without any parameters (but ``None``
    is also accepted):

    >>> OCSPNoCheckModel()
    OCSPNoCheckModel(critical=False)
    >>> OCSPNoCheckModel(value=None, critical=True)
    OCSPNoCheckModel(critical=True)
    """

    _extension_type = x509.OCSPNoCheck
    type: Literal["ocsp_no_check"] = Field(default="ocsp_no_check", repr=False)
    critical: bool = EXTENSION_DEFAULT_CRITICAL[ExtensionOID.OCSP_NO_CHECK]


class PolicyConstraintsModel(ExtensionModel[x509.PolicyConstraints]):
    """Pydantic model for a :py:class:`~cg:cryptography.x509.PolicyConstraints` extension.

    The `value` is a :py:class:`~django_ca.pydantic.extension_attributes.PolicyConstraintsValueModel`
    instance:

    >>> value = PolicyConstraintsValueModel(require_explicit_policy=0, inhibit_policy_mapping=1)
    >>> PolicyConstraintsModel(value=value)  # doctest: +STRIP_WHITESPACE
    PolicyConstraintsModel(
        critical=True,
        value=PolicyConstraintsValueModel(require_explicit_policy=0, inhibit_policy_mapping=1)
    )
    """

    model_config = ConfigDict(from_attributes=True)
    type: Literal["policy_constraints"] = Field(default="policy_constraints", repr=False)
    critical: bool = EXTENSION_DEFAULT_CRITICAL[ExtensionOID.POLICY_CONSTRAINTS]
    value: PolicyConstraintsValueModel
    requires_critical: ClassVar[bool] = True  # MUST mark this extension as critical

    @property
    def extension_type(self) -> x509.PolicyConstraints:
        """The :py:class:`~cg:cryptography.x509.PolicyConstraints` instance."""
        return self.value.cryptography


class PrecertPoisonModel(NoValueExtensionModel[x509.PrecertPoison]):
    """Pydantic model for a :py:class:`~cg:cryptography.x509.PrecertPoison` extension.

    This extension does not have a value, and thus can be instantiated without any parameters (but ``None``
    is also accepted):

    >>> PrecertPoisonModel()
    PrecertPoisonModel(critical=True)
    >>> PrecertPoisonModel(value=None, critical=True)
    PrecertPoisonModel(critical=True)
    """

    _extension_type = x509.PrecertPoison
    type: Literal["precert_poison"] = Field(default="precert_poison", repr=False)
    critical: bool = EXTENSION_DEFAULT_CRITICAL[ExtensionOID.PRECERT_POISON]
    requires_critical: ClassVar[bool] = True  # RFC 6962: "critical poison extension"


class PrecertificateSignedCertificateTimestampsModel(
    SignedCertificateTimestampBaseModel[x509.PrecertificateSignedCertificateTimestamps]
):
    """Model for a :py:class:`~cg:cryptography.x509.PrecertificateSignedCertificateTimestamps` extension.

    .. NOTE::

       Due to library limitations, this model cannot be converted to a cryptography class.

    The `value` is a list of
    :py:class:`~django_ca.pydantic.extension_attributes.SignedCertificateTimestampModel` instances:

    >>> from datetime import datetime
    >>> sct = SignedCertificateTimestampModel(
    ...     log_id=b"MTIz", timestamp=datetime(2023, 12, 10), entry_type="precertificate"
    ... )
    >>> PrecertificateSignedCertificateTimestampsModel(
    ...     value=[sct]
    ... )  # doctest: +STRIP_WHITESPACE
    PrecertificateSignedCertificateTimestampsModel(
        critical=False,
        value=[
            SignedCertificateTimestampModel(
                version='v1',
                log_id=b'123',
                timestamp=datetime.datetime(2023, 12, 10, 0, 0),
                entry_type='precertificate'
            )
        ]
    )
    """

    _extension_type = x509.PrecertificateSignedCertificateTimestamps
    type: Literal["precertificate_signed_certificate_timestamps"] = Field(
        default="precertificate_signed_certificate_timestamps", repr=False
    )
    critical: bool = EXTENSION_DEFAULT_CRITICAL[ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS]


class SignedCertificateTimestampsModel(SignedCertificateTimestampBaseModel[x509.SignedCertificateTimestamps]):
    """Pydantic model for a :py:class:`~cg:cryptography.x509.SignedCertificateTimestamps` extension.

    This model behaves exactly like
    :py:class:`~django_ca.pydantic.extensions.PrecertificateSignedCertificateTimestampsModel`.
    """

    _extension_type = x509.SignedCertificateTimestamps
    type: Literal["signed_certificate_timestamps"] = Field(
        default="signed_certificate_timestamps", repr=False
    )
    critical: bool = EXTENSION_DEFAULT_CRITICAL[ExtensionOID.SIGNED_CERTIFICATE_TIMESTAMPS]


class SubjectAlternativeNameModel(AlternativeNameBaseModel[x509.SubjectAlternativeName]):
    """Pydantic model for a :py:class:`~cg:cryptography.x509.SubjectAlternativeName` extension.

    The `general_names` attribute is a list of :py:class:`~django_ca.pydantic.general_name.GeneralNameModel`
    instances:

    >>> name1 = {"type": "DNS", "value": "example.com"}
    >>> name2 = {"type": "DNS", "value": "example.net"}
    >>> SubjectAlternativeNameModel(value=[name1, name2])  # doctest: +STRIP_WHITESPACE
    SubjectAlternativeNameModel(
        critical=False,
        value=[
            GeneralNameModel(type='DNS', value='example.com'),
            GeneralNameModel(type='DNS', value='example.net')
        ]
    )
    """

    _extension_type = x509.SubjectAlternativeName
    type: Literal["subject_alternative_name"] = Field(default="subject_alternative_name", repr=False)
    critical: bool = EXTENSION_DEFAULT_CRITICAL[ExtensionOID.SUBJECT_ALTERNATIVE_NAME]


class SubjectInformationAccessModel(InformationAccessBaseModel[x509.SubjectInformationAccess]):
    """Pydantic model for a :py:class:`~cg:cryptography.x509.SubjectInformationAccess` extension.

    This model behaves like the
    :py:class:`~django_ca.pydantic.extensions.AuthorityInformationAccessModel`, except that the access
    methods have to be `ca_repository`:

    >>> access_description = AccessDescriptionModel(
    ...     access_method='ca_repository',
    ...     access_location={'type': 'URI', 'value': 'http://example.com'}
    ... )
    >>> SubjectInformationAccessModel(value=[access_description])  # doctest: +STRIP_WHITESPACE
    SubjectInformationAccessModel(
        critical=False,
        value=[
            AccessDescriptionModel(
                access_method='1.3.6.1.5.5.7.48.5',
                access_location=GeneralNameModel(type='URI', value='http://example.com')
            )
        ]
    )
    """

    _extension_type = x509.SubjectInformationAccess
    _acceptable_oids = (SubjectInformationAccessOID.CA_REPOSITORY.dotted_string,)
    type: Literal["subject_information_access"] = Field(default="subject_information_access", repr=False)
    critical: bool = EXTENSION_DEFAULT_CRITICAL[ExtensionOID.SUBJECT_INFORMATION_ACCESS]
    requires_critical: ClassVar[bool] = False  # MUST mark this extension as non-critical


class SubjectKeyIdentifierModel(ExtensionModel[x509.SubjectKeyIdentifier]):
    """Pydantic model for a :py:class:`~cg:cryptography.x509.SubjectKeyIdentifier` extension.

    The `value` is a base64-encoded ``bytes`` instance:

    >>> SubjectKeyIdentifierModel(value=b"kA==")
    SubjectKeyIdentifierModel(critical=False, value=b'\\x90')
    """

    type: Literal["subject_key_identifier"] = Field(default="subject_key_identifier", repr=False)
    critical: bool = EXTENSION_DEFAULT_CRITICAL[ExtensionOID.SUBJECT_KEY_IDENTIFIER]
    value: Base64Bytes
    requires_critical: ClassVar[bool] = False  # MUST mark this extension as non-critical

    @model_validator(mode="before")
    @classmethod
    def parse_cryptography(cls, data: Any) -> Any:
        """Parse cryptography instances."""
        if isinstance(data, x509.Extension) and isinstance(data.value, x509.SubjectKeyIdentifier):
            return {"critical": data.critical, "value": base64.b64encode(data.value.digest)}
        return data

    @property
    def extension_type(self) -> x509.SubjectKeyIdentifier:
        """The :py:class:`~cg:cryptography.x509.SubjectKeyIdentifier` instance."""
        return x509.SubjectKeyIdentifier(digest=self.value)


class TLSFeatureModel(ExtensionModel[x509.TLSFeature]):
    """Pydantic model for a :py:class:`~cg:cryptography.x509.TLSFeature` extension.

    The `value` is a list of one or both of ``"status_request"`` and ``"status_request_v2"``.

    >>> TLSFeatureModel(value=["status_request"])
    TLSFeatureModel(critical=False, value=['status_request'])

    For convenience, the model also accepts keys named in :py:attr:`~django_ca.constants.TLS_FEATURE_NAMES`:

    >>> TLSFeatureModel(value=["OCSPMustStaple"])
    TLSFeatureModel(critical=False, value=['status_request'])
    """

    model_config = ConfigDict(from_attributes=True)
    type: Literal["tls_feature"] = Field(default="tls_feature", repr=False)
    critical: bool = EXTENSION_DEFAULT_CRITICAL[ExtensionOID.TLS_FEATURE]
    value: NonEmptyOrderedSet[
        list[
            Annotated[
                Literal["status_request", "status_request_v2"],
                BeforeValidator(validators.tls_feature_validator),
            ]
        ]
    ]

    @property
    def extension_type(self) -> x509.TLSFeature:
        """The :py:class:`~cg:cryptography.x509.TLSFeature` instance."""
        features = [getattr(x509.TLSFeatureType, feature) for feature in self.value]
        return x509.TLSFeature(features=features)


class UnrecognizedExtensionModel(ExtensionModel[x509.UnrecognizedExtension]):
    """Pydantic model for a :py:class:`~cg:cryptography.x509.UnrecognizedExtension` extension.

    The `value` a :py:class:`~django_ca.pydantic.extension_attributes.UnrecognizedExtensionValueModel` value:

    >>> value = UnrecognizedExtensionValueModel(value=b"MTIz", oid="1.2.3")
    >>> UnrecognizedExtensionModel(critical=True, value=value)  # doctest: +STRIP_WHITESPACE
    UnrecognizedExtensionModel(
        critical=True, value=UnrecognizedExtensionValueModel(oid='1.2.3', value=b'123')
    )
    """

    model_config = ConfigDict(from_attributes=True)
    type: Literal["unknown"] = Field(default="unknown", repr=False)
    critical: bool
    value: UnrecognizedExtensionValueModel

    @property
    def cryptography(self) -> x509.Extension[x509.UnrecognizedExtension]:  # type: ignore[override]
        """Return the respective cryptography instance."""
        value = self.extension_type
        return x509.Extension(critical=self.critical, oid=value.oid, value=value)

    @property
    def extension_type(self) -> x509.UnrecognizedExtension:
        """The :py:class:`~cg:cryptography.x509.UnrecognizedExtension` instance."""
        return self.value.cryptography


EXTENSION_MODEL_OIDS: "MappingProxyType[type[ExtensionModel[Any]], x509.ObjectIdentifier]" = MappingProxyType(
    {
        AuthorityInformationAccessModel: ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
        AuthorityKeyIdentifierModel: ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
        BasicConstraintsModel: ExtensionOID.BASIC_CONSTRAINTS,
        CRLDistributionPointsModel: ExtensionOID.CRL_DISTRIBUTION_POINTS,
        CRLNumberModel: ExtensionOID.CRL_NUMBER,
        CertificatePoliciesModel: ExtensionOID.CERTIFICATE_POLICIES,
        DeltaCRLIndicatorModel: ExtensionOID.DELTA_CRL_INDICATOR,
        ExtendedKeyUsageModel: ExtensionOID.EXTENDED_KEY_USAGE,
        FreshestCRLModel: ExtensionOID.FRESHEST_CRL,
        InhibitAnyPolicyModel: ExtensionOID.INHIBIT_ANY_POLICY,
        IssuerAlternativeNameModel: ExtensionOID.ISSUER_ALTERNATIVE_NAME,
        IssuingDistributionPointModel: ExtensionOID.ISSUING_DISTRIBUTION_POINT,
        KeyUsageModel: ExtensionOID.KEY_USAGE,
        MSCertificateTemplateModel: ExtensionOID.MS_CERTIFICATE_TEMPLATE,
        NameConstraintsModel: ExtensionOID.NAME_CONSTRAINTS,
        OCSPNoCheckModel: ExtensionOID.OCSP_NO_CHECK,
        PolicyConstraintsModel: ExtensionOID.POLICY_CONSTRAINTS,
        PrecertPoisonModel: ExtensionOID.PRECERT_POISON,
        PrecertificateSignedCertificateTimestampsModel: ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS,
        SignedCertificateTimestampsModel: ExtensionOID.SIGNED_CERTIFICATE_TIMESTAMPS,
        SubjectAlternativeNameModel: ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
        SubjectInformationAccessModel: ExtensionOID.SUBJECT_INFORMATION_ACCESS,
        SubjectKeyIdentifierModel: ExtensionOID.SUBJECT_KEY_IDENTIFIER,
        TLSFeatureModel: ExtensionOID.TLS_FEATURE,
    }
)
EXTENSION_MODELS: "MappingProxyType[x509.ObjectIdentifier, type[ExtensionModel[Any]]]" = MappingProxyType(
    {v: k for k, v in EXTENSION_MODEL_OIDS.items()}
)


def validate_cryptograph_extensions(v: Any, info: ValidationInfo) -> Any:
    """Parse a cryptography extension into a Pydantic model."""
    if isinstance(v, x509.Extension):
        if isinstance(v.value, x509.UnrecognizedExtension):
            model_class: type[ExtensionModel[Any]] = UnrecognizedExtensionModel
        else:
            model_class = EXTENSION_MODELS[v.oid]
        return model_class.model_validate(v, context=info.context)
    return v


#: Union type for extensions that may occur as input when signing a certificate.
SignCertificateExtensions = Annotated[
    Annotated[
        Union[
            AuthorityInformationAccessModel,
            CertificatePoliciesModel,
            CRLDistributionPointsModel,
            ExtendedKeyUsageModel,
            FreshestCRLModel,
            IssuerAlternativeNameModel,
            KeyUsageModel,
            OCSPNoCheckModel,
            SubjectAlternativeNameModel,
            TLSFeatureModel,
        ],
        Field(discriminator="type"),
    ],
    BeforeValidator(validate_cryptograph_extensions),
]

#: Union type for all known extensions that may occur in any type of certificate.
CertificateExtensionsType = Annotated[
    Annotated[
        Union[
            AuthorityInformationAccessModel,
            AuthorityKeyIdentifierModel,
            BasicConstraintsModel,
            CRLDistributionPointsModel,
            CertificatePoliciesModel,
            ExtendedKeyUsageModel,
            FreshestCRLModel,
            InhibitAnyPolicyModel,
            IssuerAlternativeNameModel,
            KeyUsageModel,
            MSCertificateTemplateModel,
            NameConstraintsModel,
            OCSPNoCheckModel,
            PolicyConstraintsModel,
            PrecertPoisonModel,
            PrecertificateSignedCertificateTimestampsModel,
            SignedCertificateTimestampsModel,
            SubjectAlternativeNameModel,
            SubjectInformationAccessModel,
            SubjectKeyIdentifierModel,
            TLSFeatureModel,
            UnrecognizedExtensionModel,
        ],
        Field(discriminator="type"),
    ],
    BeforeValidator(validate_cryptograph_extensions),
]

CertificateExtensions = TypeAdapter(CertificateExtensionsType)
SignCertificateExtensionsList = TypeAdapter(list[SignCertificateExtensions])
CertificateExtensionsList = TypeAdapter(list[CertificateExtensionsType])

ExtensionModelTypeVar = TypeVar("ExtensionModelTypeVar", bound=ExtensionModel[Any])
