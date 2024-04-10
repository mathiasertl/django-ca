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

"""Some extensions use a more complex datastructure, so attributes are represented as nested models."""

import base64
from datetime import datetime
from typing import Annotated, Any, Literal, NoReturn, Optional, Union

from pydantic import AfterValidator, Base64Bytes, BeforeValidator, ConfigDict, Field, model_validator

from cryptography import x509
from cryptography.x509 import certificate_transparency
from cryptography.x509.oid import CertificatePoliciesOID

from django_ca import constants
from django_ca.pydantic import validators
from django_ca.pydantic.base import CryptographyModel
from django_ca.pydantic.general_name import GeneralNameModel
from django_ca.pydantic.name import NameModel
from django_ca.pydantic.type_aliases import NonEmptyOrderedSet, OIDType
from django_ca.typehints import DistributionPointReasons, LogEntryTypes

_NOTICE_REFERENCE_DESCRIPTION = (
    "A NoticeReferenceModel consists of an optional *organization* and an optional list of *notice_numbers*."
)


class AccessDescriptionModel(CryptographyModel[x509.AccessDescription]):
    """Pydantic model wrapping :py:class:`~cg:cryptography.x509.AccessDescription`.

    The `access_method` may be a dotted string OID or one of the aliases listed in
    :py:attr:`~django_ca.constants.ACCESS_METHOD_TYPES`. The `access_location` is a
    :py:class:`~django_ca.pydantic.general_name.GeneralNameModel`:

    .. pydantic-model:: access_description_ocsp

    The syntax is identical for CA issuers:

    .. pydantic-model:: access_description_ca_issuers
    """

    model_config = ConfigDict(from_attributes=True)

    access_method: Annotated[
        str,
        BeforeValidator(validators.oid_parser),
        BeforeValidator(validators.access_method_parser),
        AfterValidator(validators.oid_validator),
    ]
    access_location: GeneralNameModel

    @property
    def cryptography(self) -> x509.AccessDescription:
        """Convert to a :py:class:`~cg:cryptography.x509.AccessDescription` instance."""
        return x509.AccessDescription(
            access_method=x509.ObjectIdentifier(self.access_method),
            access_location=self.access_location.cryptography,
        )


class AuthorityKeyIdentifierValueModel(CryptographyModel[x509.AuthorityKeyIdentifier]):
    """Pydantic model wrapping :py:class:`~cg:cryptography.x509.AuthorityKeyIdentifier`.

    In its by far most common form, this model will just set the `key_identifier` attribute, with a value
    based on the certificate authority. Since this is a ``bytes`` value, the input must be base64 encoded:

    >>> AuthorityKeyIdentifierValueModel(key_identifier=b"MTIz")  # doctest: +STRIP_WHITESPACE
    AuthorityKeyIdentifierValueModel(
        key_identifier=b'123', authority_cert_issuer=None, authority_cert_serial_number=None
    )

    You can also give a `authority_cert_issuer` (a list of
    :py:class:`~django_ca.pydantic.general_name.GeneralNameModel`) and an `authority_cert_serial_number`:

    >>> AuthorityKeyIdentifierValueModel(
    ...     key_identifier=None,
    ...     authority_cert_issuer=[{'type': 'URI', 'value': 'http://example.com'}],
    ...     authority_cert_serial_number=123
    ... )  # doctest: +STRIP_WHITESPACE
    AuthorityKeyIdentifierValueModel(
        key_identifier=None,
        authority_cert_issuer=[GeneralNameModel(type='URI', value='http://example.com')],
        authority_cert_serial_number=123
    )

    The restrictions defined in RFC 5280 apply, so `authority_cert_issuer` and `authority_cert_serial_number`
    must either be both present or ``None``, and either `key_identifier` and/or `authority_cert_issuer` must
    be given.
    """

    key_identifier: Optional[Base64Bytes]
    authority_cert_issuer: Optional[list[GeneralNameModel]] = None
    authority_cert_serial_number: Optional[int] = None

    @model_validator(mode="before")
    @classmethod
    def parse_cryptography(cls, data: Any) -> Any:
        """Parse cryptography instance."""
        if isinstance(data, x509.AuthorityKeyIdentifier):
            key_identifier = None
            if data.key_identifier is not None:
                key_identifier = base64.b64encode(data.key_identifier)

            return {
                "key_identifier": key_identifier,
                "authority_cert_issuer": data.authority_cert_issuer,
                "authority_cert_serial_number": data.authority_cert_serial_number,
            }
        return data

    @model_validator(mode="after")
    # pylint: disable-next=missing-function-docstring
    def check_consistency(self) -> "AuthorityKeyIdentifierValueModel":
        if (self.authority_cert_issuer is None) != (self.authority_cert_serial_number is None):
            raise ValueError(
                "authority_cert_issuer and authority_cert_serial_number must both be present or both None"
            )
        if self.key_identifier is None and self.authority_cert_issuer is None:
            raise ValueError(
                "At least one of key_identifier or "
                "authority_cert_issuer/authority_cert_serial_number must be given."
            )
        return self

    @property
    def cryptography(self) -> x509.AuthorityKeyIdentifier:
        """Convert to a :py:class:`~cg:cryptography.x509.AuthorityKeyIdentifier` instance."""
        authority_cert_issuer = None
        if self.authority_cert_issuer is not None:
            authority_cert_issuer = [general_name.cryptography for general_name in self.authority_cert_issuer]

        return x509.AuthorityKeyIdentifier(
            key_identifier=self.key_identifier,
            authority_cert_issuer=authority_cert_issuer,
            authority_cert_serial_number=self.authority_cert_serial_number,
        )


class BasicConstraintsValueModel(CryptographyModel[x509.BasicConstraints]):
    """Pydantic model wrapping :py:class:`~cg:cryptography.x509.BasicConstraints`.

    For a certificate representing a certificate authority, this extension sets `ca` to ``True`` and a path
    length, which may be None:

    >>> BasicConstraintsValueModel(ca=True, path_length=0)
    BasicConstraintsValueModel(ca=True, path_length=0)

    For end-entity certificates, this extension sets `ca` to ``False`` and must set `path_length` to
    ``None``:

    >>> BasicConstraintsValueModel(ca=False, path_length=None)
    BasicConstraintsValueModel(ca=False, path_length=None)
    """

    model_config = ConfigDict(from_attributes=True)

    ca: bool
    path_length: Optional[int] = Field(ge=0)

    @model_validator(mode="after")
    # pylint: disable-next=missing-function-docstring
    def check_path_length(self) -> "BasicConstraintsValueModel":
        if self.ca is False and self.path_length is not None:
            raise ValueError("path_length must be None when ca is False")
        return self

    @property
    def cryptography(self) -> x509.BasicConstraints:
        """Convert to a :py:class:`~cg:cryptography.x509.BasicConstraints` instance."""
        return x509.BasicConstraints(ca=self.ca, path_length=self.path_length)


class DistributionPointModel(CryptographyModel[x509.DistributionPoint]):
    """Pydantic model wrapping :py:class:`~cg:cryptography.x509.DistributionPoint`.

    In its by far most common form, this model only has a `full_name` containing a URI:

    >>> DistributionPointModel(
    ...     full_name=[{"type": "URI", "value": "https://ca.example.com/crl"}]
    ... )  # doctest: +STRIP_WHITESPACE
    DistributionPointModel(
        full_name=[GeneralNameModel(type='URI', value='https://ca.example.com/crl')],
        relative_name=None, crl_issuer=None, reasons=None
    )

    Of course, other fields are also supported:

    >>> DistributionPointModel(
    ...     relative_name=[{"oid": "2.5.4.3", "value": "example.com"}],
    ...     crl_issuer=[{"type": "URI", "value": "https://ca.example.com/issuer"}],
    ...     reasons={"key_compromise",}
    ... )  # doctest: +STRIP_WHITESPACE
    DistributionPointModel(
        full_name=None,
        relative_name=NameModel(root=[NameAttributeModel(oid='2.5.4.3', value='example.com')]),
        crl_issuer=[GeneralNameModel(type='URI', value='https://ca.example.com/issuer')],
        reasons={'key_compromise'}
    )
    """

    model_config = ConfigDict(from_attributes=True)

    full_name: Optional[list[GeneralNameModel]] = None
    relative_name: Optional[NameModel] = None
    crl_issuer: Optional[list[GeneralNameModel]] = None
    reasons: Optional[set[DistributionPointReasons]] = None

    @model_validator(mode="before")
    @classmethod
    def parse_cryptography(cls, data: Any) -> Any:  # pylint: disable=missing-function-docstring
        if isinstance(data, x509.DistributionPoint):
            reasons = None
            if data.reasons:
                reasons = [reason.name for reason in data.reasons]

            return DistributionPointModel(
                full_name=data.full_name,
                relative_name=data.relative_name,
                crl_issuer=data.crl_issuer,
                reasons=reasons,
            )

        return data

    @model_validator(mode="after")
    # pylint: disable-next=missing-function-docstring
    def check_consistency(self) -> "DistributionPointModel":
        if self.full_name and self.relative_name:
            raise ValueError("must give exactly one of full_name or relative_name.")
        if not self.full_name and not self.relative_name and not self.crl_issuer:
            raise ValueError("either full_name, relative_name or crl_issuer must be provided.")

        return self

    @property
    def cryptography(self) -> x509.DistributionPoint:
        """Convert to a :py:class:`~cg:cryptography.x509.DistributionPoint` instance."""
        full_name = relative_name = crl_issuer = reasons = None
        if self.full_name:
            full_name = [name.cryptography for name in self.full_name]
        elif self.relative_name is not None:  # pragma: no branch
            relative_name = x509.RelativeDistinguishedName(self.relative_name.cryptography)

        if self.crl_issuer:
            crl_issuer = [name.cryptography for name in self.crl_issuer]
        if self.reasons:
            reasons = frozenset(x509.ReasonFlags[reason] for reason in self.reasons)
        return x509.DistributionPoint(
            full_name=full_name, relative_name=relative_name, crl_issuer=crl_issuer, reasons=reasons
        )


class IssuingDistributionPointValueModel(CryptographyModel[x509.IssuingDistributionPoint]):
    """Pydantic model wrapping :py:class:`~cg:cryptography.x509.IssuingDistributionPoint`.

    >>> full_name = [{"type": "URI", "value": "https://ca.example.com/crl"}]
    >>> IssuingDistributionPointValueModel(full_name=full_name)  # doctest: +STRIP_WHITESPACE
    IssuingDistributionPointValueModel(
        only_contains_user_certs=False,
        only_contains_ca_certs=False,
        indirect_crl=False,
        only_contains_attribute_certs=False,
        only_some_reasons=None,
        full_name=[GeneralNameModel(type='URI', value='https://ca.example.com/crl')],
        relative_name=None
    )

    Note that all attributes default to False or None and can thus be omitted, but at least one parameter
    needs to be given.
    """

    model_config = ConfigDict(from_attributes=True)
    only_contains_user_certs: bool = False
    only_contains_ca_certs: bool = False
    indirect_crl: bool = False
    only_contains_attribute_certs: bool = False
    only_some_reasons: Optional[set[DistributionPointReasons]] = None
    full_name: Optional[NonEmptyOrderedSet[list[GeneralNameModel]]] = None
    relative_name: Optional[NameModel] = None

    @model_validator(mode="before")
    @classmethod
    def parse_cryptography(cls, data: Any) -> Any:  # pylint: disable=missing-function-docstring
        if isinstance(data, x509.IssuingDistributionPoint):
            reasons = None
            if data.only_some_reasons:
                reasons = [reason.name for reason in data.only_some_reasons]

            return IssuingDistributionPointValueModel(
                only_contains_user_certs=data.only_contains_user_certs,
                only_contains_ca_certs=data.only_contains_ca_certs,
                indirect_crl=data.indirect_crl,
                only_contains_attribute_certs=data.only_contains_attribute_certs,
                only_some_reasons=reasons,
                full_name=data.full_name,
                relative_name=data.relative_name,
            )

        return data

    @model_validator(mode="after")
    # pylint: disable-next=missing-function-docstring
    def check_consistency(self) -> "IssuingDistributionPointValueModel":
        if self.full_name and self.relative_name:
            raise ValueError("only one of full_name or relative_name may be True")

        crl_constraints = [
            self.only_contains_user_certs,
            self.only_contains_ca_certs,
            self.indirect_crl,
            self.only_contains_attribute_certs,
        ]
        if len([x for x in crl_constraints if x]) > 1:
            raise ValueError(
                "only one can be set: only_contains_user_certs, only_contains_ca_certs, indirect_crl, "
                "only_contains_attribute_certs"
            )

        if not any((*crl_constraints, self.only_some_reasons, self.full_name, self.relative_name)):
            raise ValueError("cannot create empty extension")

        return self

    @property
    def cryptography(self) -> x509.IssuingDistributionPoint:
        """Convert to a :py:class:`~cg:cryptography.x509.IssuingDistributionPoint` instance."""
        full_name = relative_name = reasons = None
        if self.full_name is not None:
            full_name = [general_name.cryptography for general_name in self.full_name]
        if self.relative_name is not None:
            relative_name = x509.RelativeDistinguishedName(self.relative_name.cryptography)
        if self.only_some_reasons:
            reasons = frozenset(x509.ReasonFlags[reason] for reason in self.only_some_reasons)

        return x509.IssuingDistributionPoint(
            only_contains_user_certs=self.only_contains_user_certs,
            only_contains_ca_certs=self.only_contains_ca_certs,
            indirect_crl=self.indirect_crl,
            only_contains_attribute_certs=self.only_contains_attribute_certs,
            only_some_reasons=reasons,
            full_name=full_name,
            relative_name=relative_name,
        )


class SignedCertificateTimestampModel(CryptographyModel[certificate_transparency.SignedCertificateTimestamp]):
    """Pydantic model wrapping ``SignedCertificateTimestamp``.

    .. NOTE::

       Due to library limitations, this model cannot be converted to a cryptography class.

    >>> SignedCertificateTimestampModel(
    ...     log_id=b"MTIz", timestamp=datetime(2023, 12, 10), entry_type="precertificate"
    ... )  # doctest: +STRIP_WHITESPACE
    SignedCertificateTimestampModel(
        version='v1',
        log_id=b'123',
        timestamp=datetime.datetime(2023, 12, 10, 0, 0),
        entry_type='precertificate'
    )
    """

    model_config = ConfigDict(from_attributes=True)

    version: Literal["v1"] = "v1"
    log_id: Base64Bytes
    timestamp: datetime
    entry_type: LogEntryTypes

    @model_validator(mode="before")
    @classmethod
    def parse_cryptography(cls, data: Any) -> Any:  # pylint: disable=missing-function-docstring
        if isinstance(data, certificate_transparency.SignedCertificateTimestamp):
            return {
                "version": data.version.name,
                "log_id": base64.b64encode(data.log_id),
                "timestamp": data.timestamp,
                "entry_type": constants.LOG_ENTRY_TYPE_KEYS[data.entry_type],
            }

        return data  # pragma: no cover

    @property
    def cryptography(self) -> NoReturn:  # # pragma: no cover
        """Will always raise an exception for this class."""
        raise ValueError("SignedCertificateTimestamps cannot be loaded as cryptography instances.")


class MSCertificateTemplateValueModel(CryptographyModel[x509.MSCertificateTemplate]):
    """Pydantic model wrapping :py:class:`~cg:cryptography.x509.MSCertificateTemplate`.

    The `template_id` parameter is a dotted-string object identifier, while `major_version` and
    `minor_version` are optional integers:

    >>> MSCertificateTemplateValueModel(template_id="1.2.3", major_version=1)
    MSCertificateTemplateValueModel(template_id='1.2.3', major_version=1, minor_version=None)
    """

    model_config = ConfigDict(from_attributes=True)
    template_id: OIDType
    major_version: Optional[int] = None
    minor_version: Optional[int] = None

    @property
    def cryptography(self) -> x509.MSCertificateTemplate:
        """Convert to a :py:class:`~cg:cryptography.x509.MSCertificateTemplate` instance."""
        return x509.MSCertificateTemplate(
            template_id=x509.ObjectIdentifier(self.template_id),
            major_version=self.major_version,
            minor_version=self.minor_version,
        )


class NameConstraintsValueModel(CryptographyModel[x509.NameConstraints]):
    """Pydantic model wrapping :py:class:`~cg:cryptography.x509.NameConstraints`.

    Both `permitted_subtrees` and `excluded_subtrees` are optional, but at least one of them must be given.
    They are a list of :py:class:`~django_ca.pydantic.general_name.GeneralNameModel` instances:

    >>> NameConstraintsValueModel(
    ...     permitted_subtrees=[{"type": "DNS", "value": ".com"}]
    ... )  # doctest: +STRIP_WHITESPACE
    NameConstraintsValueModel(
        permitted_subtrees=[GeneralNameModel(type='DNS', value='.com')], excluded_subtrees=None
    )
    """

    model_config = ConfigDict(from_attributes=True)
    permitted_subtrees: Optional[NonEmptyOrderedSet[list[GeneralNameModel]]] = None
    excluded_subtrees: Optional[NonEmptyOrderedSet[list[GeneralNameModel]]] = None

    @model_validator(mode="after")
    # pylint: disable-next=missing-function-docstring
    def check_at_least_one_given(self) -> "NameConstraintsValueModel":
        if self.permitted_subtrees is None and self.excluded_subtrees is None:
            raise ValueError("At least one of permitted_subtrees and excluded_subtrees must not be None")
        return self

    @property
    def cryptography(self) -> x509.NameConstraints:
        """Convert to a :py:class:`~cg:cryptography.x509.NameConstraints` instance."""
        permitted = excluded = None
        if self.permitted_subtrees is not None:
            permitted = [name.cryptography for name in self.permitted_subtrees]
        if self.excluded_subtrees is not None:
            excluded = [name.cryptography for name in self.excluded_subtrees]
        return x509.NameConstraints(permitted_subtrees=permitted, excluded_subtrees=excluded)


class NoticeReferenceModel(CryptographyModel[x509.NoticeReference]):
    """Pydantic model wrapping :py:class:`~cg:cryptography.x509.NoticeReference`.

    >>> NoticeReferenceModel(organization="MyOrg", notice_numbers=[1, 2, 3])
    NoticeReferenceModel(organization='MyOrg', notice_numbers=[1, 2, 3])

    Note that `organization` is optional.
    """

    model_config = ConfigDict(
        from_attributes=True, json_schema_extra={"description": _NOTICE_REFERENCE_DESCRIPTION}
    )

    organization: Optional[str] = None
    notice_numbers: list[int]

    @property
    def cryptography(self) -> x509.NoticeReference:
        """Convert to a :py:class:`~cg:cryptography.x509.NoticeReference` instance."""
        return x509.NoticeReference(organization=self.organization, notice_numbers=self.notice_numbers)


class PolicyConstraintsValueModel(CryptographyModel[x509.PolicyConstraints]):
    """Pydantic model wrapping :py:class:`~cg:cryptography.x509.PolicyConstraints`.

    The `require_explicit_policy` and `inhibit_policy_mapping` are both optional and must be integers if set.
    At least one value must be given.

    >>> PolicyConstraintsValueModel(require_explicit_policy=0, inhibit_policy_mapping=1)
    PolicyConstraintsValueModel(require_explicit_policy=0, inhibit_policy_mapping=1)
    """

    model_config = ConfigDict(from_attributes=True)
    require_explicit_policy: Optional[int] = Field(ge=0)
    inhibit_policy_mapping: Optional[int] = Field(ge=0)

    @model_validator(mode="after")
    # pylint: disable-next=missing-function-docstring
    def check_consistency(self) -> "PolicyConstraintsValueModel":
        if self.require_explicit_policy is None and self.inhibit_policy_mapping is None:
            raise ValueError(
                "At least one of require_explicit_policy and inhibit_policy_mapping must not be None"
            )

        return self

    @property
    def cryptography(self) -> x509.PolicyConstraints:
        """Convert to a :py:class:`~cg:cryptography.x509.PolicyConstraints` instance."""
        return x509.PolicyConstraints(
            require_explicit_policy=self.require_explicit_policy,
            inhibit_policy_mapping=self.inhibit_policy_mapping,
        )


class UserNoticeModel(CryptographyModel[x509.UserNotice]):
    """Pydantic model wrapping :py:class:`~cg:cryptography.x509.UserNotice`.

    In its simplest form, the model can just take an explicit text:

    >>> UserNoticeModel(explicit_text="my text")
    UserNoticeModel(notice_reference=None, explicit_text='my text')

    But it may also take notice reference:

    >>> ref = NoticeReferenceModel(notice_numbers=[1, 2, 3])
    >>> UserNoticeModel(notice_reference=ref, explicit_text="my text")  # doctest: +NORMALIZE_WHITESPACE
    UserNoticeModel(notice_reference=NoticeReferenceModel(organization=None,
                        notice_numbers=[1, 2, 3]),
                    explicit_text='my text')

    """

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "description": "A UserNoticeModel consists of an *explicit_text* and an optional "
            "*notice_reference*."
        },
    )

    notice_reference: Optional[NoticeReferenceModel] = None
    explicit_text: Optional[str]

    @property
    def cryptography(self) -> x509.UserNotice:
        """Convert to a :py:class:`~cg:cryptography.x509.UserNotice` instance."""
        notice_reference = None
        if self.notice_reference is not None:
            notice_reference = self.notice_reference.cryptography
        return x509.UserNotice(notice_reference=notice_reference, explicit_text=self.explicit_text)


class PolicyInformationModel(CryptographyModel[x509.PolicyInformation]):
    """Pydantic model wrapping :py:class:`~cg:cryptography.x509.PolicyInformation`.

    In its simplest for, this model requires only a `policy_identifier`:

    >>> PolicyInformationModel(policy_identifier="2.5.29.32.0")
    PolicyInformationModel(policy_identifier='2.5.29.32.0', policy_qualifiers=None)

    A list of `policy_qualifiers` may also be passed, with elements being either a ``str`` or a
    :py:class:`~django_ca.pydantic.extension_attributes.UserNoticeModel`:

    >>> notice = UserNoticeModel(explicit_text="my text")
    >>> PolicyInformationModel(
    ...     policy_identifier="1.3.6.1.5.5.7.2.1",
    ...     policy_qualifiers=["https://ca.example.com/cps", notice]
    ... )  # doctest: +STRIP_WHITESPACE
    PolicyInformationModel(
        policy_identifier='1.3.6.1.5.5.7.2.1',
        policy_qualifiers=[
            'https://ca.example.com/cps',
            UserNoticeModel(notice_reference=None, explicit_text='my text')
        ]
    )
    """

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "description": "A PolicyInformationModel consists of a *policy_identifier* and an optional list "
            "*policy_qualifiers*."
        },
    )

    policy_identifier: OIDType = Field(
        description="An object identifier (OID) as dotted string.",
        json_schema_extra={"example": CertificatePoliciesOID.ANY_POLICY.dotted_string},
    )
    policy_qualifiers: Optional[list[Union[str, UserNoticeModel]]] = Field(
        default=None,
        description="Optional list of policy qualifiers, a list of strings and/or UserNoticeModel objects.",
        json_schema_extra={"example": ["http://ca.example.com/cps", {"explicit_text": "Some text."}]},
    )

    @property
    def cryptography(self) -> x509.PolicyInformation:
        """Convert to a :py:class:`~cg:cryptography.x509.PolicyInformation` instance."""
        oid = x509.ObjectIdentifier(self.policy_identifier)
        policy_qualifiers: Optional[list[Union[str, x509.UserNotice]]] = None
        if self.policy_qualifiers is not None:
            policy_qualifiers = []
            for qualifier in self.policy_qualifiers:
                if isinstance(qualifier, str):
                    policy_qualifiers.append(qualifier)
                else:
                    policy_qualifiers.append(qualifier.cryptography)
        return x509.PolicyInformation(policy_identifier=oid, policy_qualifiers=policy_qualifiers)


class UnrecognizedExtensionValueModel(CryptographyModel[x509.UnrecognizedExtension]):
    """Pydantic model for a :py:class:`~cg:cryptography.x509.UnrecognizedExtension` extension.

    The `value` a base64 encoded bytes value, and the `oid` is any dotted string:

    >>> UnrecognizedExtensionValueModel(value=b"MTIz", oid="1.2.3")
    UnrecognizedExtensionValueModel(oid='1.2.3', value=b'123')
    """

    oid: OIDType
    value: Base64Bytes

    @model_validator(mode="before")
    @classmethod
    def parse_cryptography(cls, data: Any) -> Any:
        """Parse cryptography instances."""
        if isinstance(data, x509.UnrecognizedExtension):
            return {"oid": data.oid, "value": base64.b64encode(data.value)}
        return data

    @property
    def cryptography(self) -> x509.UnrecognizedExtension:
        """The :py:class:`~cg:cryptography.x509.UnrecognizedExtension` instance."""
        return x509.UnrecognizedExtension(value=self.value, oid=x509.ObjectIdentifier(self.oid))
