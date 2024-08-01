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

"""Collection of argparse actions for django-ca management commands."""

import abc
import argparse
import getpass
import typing
from datetime import timedelta
from typing import Any, Optional

from pydantic import BaseModel

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding

from django.core.exceptions import ValidationError
from django.core.validators import URLValidator

from django_ca import constants
from django_ca.conf import model_settings
from django_ca.constants import EXTENSION_DEFAULT_CRITICAL, KEY_USAGE_NAMES, ReasonFlags
from django_ca.key_backends import KeyBackend, key_backends
from django_ca.models import Certificate, CertificateAuthority
from django_ca.pydantic.validators import is_power_two_validator
from django_ca.typehints import AllowedHashTypes, AlternativeNameExtensionType, EllipticCurves
from django_ca.utils import parse_encoding, parse_general_name

ActionType = typing.TypeVar("ActionType")  # pylint: disable=invalid-name
ParseType = typing.TypeVar("ParseType")  # pylint: disable=invalid-name
ExtensionType = typing.TypeVar("ExtensionType", bound=x509.ExtensionType)  # pylint: disable=invalid-name


def general_name_type(value: str) -> x509.GeneralName:
    """Wrapper function to parse_general_name() that sets a name."""
    return parse_general_name(value)


general_name_type.__name__ = "general name"


class SingleValueAction(argparse.Action, typing.Generic[ParseType, ActionType], metaclass=abc.ABCMeta):
    """Abstract/generic base class for arguments that take a single value.

    The main purpose of this class is to improve type hinting.
    """

    type: type[ActionType]

    @abc.abstractmethod
    def parse_value(self, value: ParseType) -> ActionType:
        """Parse the value passed to the command line. Implementing classes must implement this method.

        Parameters
        ----------
        value : str
            The value passed by the command line.
        """
        raise NotImplementedError

    def __call__(  # type: ignore[override] # argparse.Action defines much looser type
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: ParseType,
        option_string: Optional[str] = None,
    ) -> None:
        setattr(namespace, self.dest, self.parse_value(values))


class AlgorithmAction(SingleValueAction[str, AllowedHashTypes]):
    """Action for giving an algorithm.

    >>> parser = argparse.ArgumentParser()
    >>> parser.add_argument('--algorithm', action=AlgorithmAction)  # doctest: +ELLIPSIS
    AlgorithmAction(...)
    >>> parser.parse_args(['--algorithm', 'SHA-256'])  # doctest: +ELLIPSIS
    Namespace(algorithm=<cryptography.hazmat.primitives.hashes.SHA256 object at ...>)
    """

    def __init__(self, **kwargs: Any) -> None:
        hash_algorithms: set[str] = set()
        # Calculate all supported algorithms supported by any configured backend.
        for backend in key_backends:
            hash_algorithms |= set(backend.supported_hash_algorithms)

        kwargs.setdefault("choices", sorted(hash_algorithms))
        kwargs.setdefault("metavar", "{SHA-512,SHA-256,...}")
        super().__init__(**kwargs)

    def parse_value(self, value: str) -> AllowedHashTypes:
        """Parse the value for this action."""
        # NOTE: A KeyError is ruled out by the choices argument set in the constructor.
        return constants.HASH_ALGORITHM_TYPES[value]()  # type: ignore[index]


class CertificateAction(SingleValueAction[str, Certificate]):
    """Action for naming a certificate."""

    def __init__(self, allow_revoked: bool = False, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.allow_revoked = allow_revoked

    def parse_value(self, value: str) -> Certificate:
        """Parse the value for this action."""
        queryset = Certificate.objects.all()
        if self.allow_revoked is False:
            queryset = queryset.filter(revoked=False)

        try:
            return queryset.get_by_serial_or_cn(value)
        except Certificate.DoesNotExist as ex:
            raise argparse.ArgumentError(self, f"{value}: Certificate not found.") from ex
        except Certificate.MultipleObjectsReturned as ex:
            raise argparse.ArgumentError(self, f"{value}: Multiple certificates match.") from ex


class CertificateAuthorityAction(SingleValueAction[str, CertificateAuthority]):
    """Action for naming a certificate authority."""

    def __init__(self, allow_disabled: bool = False, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.allow_disabled = allow_disabled

    def parse_value(self, value: str) -> CertificateAuthority:
        """Parse the value for this action."""
        qs = CertificateAuthority.objects.all()
        if self.allow_disabled is False:
            qs = qs.enabled()

        try:
            ca = qs.get_by_serial_or_cn(value)
        except CertificateAuthority.DoesNotExist as ex:
            raise argparse.ArgumentError(self, f"{value}: Certificate authority not found.") from ex
        except CertificateAuthority.MultipleObjectsReturned as ex:
            raise argparse.ArgumentError(self, f"{value}: Multiple Certificate authorities match.") from ex

        return ca


class ExpiresAction(SingleValueAction[str, timedelta]):
    """Action for passing a timedelta in days.

    NOTE: str(timedelta) is different in python 3.6, so only outputting days here

    >>> parser = argparse.ArgumentParser()
    >>> parser.add_argument('--expires', action=ExpiresAction)  # doctest: +ELLIPSIS
    ExpiresAction(...)
    >>> parser.parse_args(['--expires', '3']).expires.days
    3
    """

    def parse_value(self, value: str) -> timedelta:
        """Parse the value for this action."""
        # NOTE: Making this a member of ExpiresAction causes an infinite loop for some reason
        try:
            days = int(value)
        except ValueError as ex:
            raise argparse.ArgumentError(self, f"{value}: Value must be an integer.") from ex
        if days <= 0:
            raise argparse.ArgumentError(self, f"{value}: Value must not be negative.")

        return timedelta(days=days)


class FormatAction(SingleValueAction[str, Encoding]):
    """Action for giving an encoding (DER/PEM).

    >>> parser = argparse.ArgumentParser()
    >>> parser.add_argument('--format', action=FormatAction)  # doctest: +ELLIPSIS
    FormatAction(...)
    >>> parser.parse_args(['--format', 'DER'])
    Namespace(format=<Encoding.DER: 'DER'>)
    """

    def parse_value(self, value: str) -> Encoding:
        """Parse the value for this action."""
        try:
            return parse_encoding(value)
        except ValueError as ex:
            raise argparse.ArgumentError(self, str(ex)) from ex


class EllipticCurveAction(SingleValueAction[EllipticCurves, ec.EllipticCurve]):
    """Action to parse an elliptic curve value.

    >>> parser = argparse.ArgumentParser()
    >>> parser.add_argument('--elliptic-curve', action=EllipticCurveAction)  # doctest: +ELLIPSIS
    EllipticCurveAction(...)
    >>> parser.parse_args(['--elliptic-curve', 'secp256r1'])  # doctest: +ELLIPSIS
    Namespace(elliptic_curve=<cryptography.hazmat.primitives.asymmetric.ec.SECP256R1 object at ...>)
    """

    def __init__(self, **kwargs: Any) -> None:
        kwargs.setdefault("choices", sorted(tuple(constants.ELLIPTIC_CURVE_TYPES)))
        kwargs.setdefault("metavar", "{secp256r1,secp384r1,secp521r1,...}")
        super().__init__(**kwargs)

    def parse_value(self, value: EllipticCurves) -> ec.EllipticCurve:
        """Parse the value for this action."""
        # NOTE: A KeyError is ruled out by the choices argument set in the constructor.
        return constants.ELLIPTIC_CURVE_TYPES[value]()


class IntegerRangeAction(SingleValueAction[int, int]):
    """An int action with an optional min/max value.

    >>> parser = argparse.ArgumentParser()
    >>> parser.add_argument('--size', action=IntegerRangeAction, min=0, max=10)  # doctest: +ELLIPSIS
    IntegerRangeAction(...)
    >>> parser.parse_args(['--size', '5'])
    Namespace(size=5)

    Parameters
    ----------
    min: int, Optional
        The optional minimum value.
    max: int, Optional
        The optional maximum value.
    """

    def __init__(self, **kwargs: Any) -> None:
        self.min = kwargs.pop("min", None)
        self.max = kwargs.pop("max", None)
        kwargs["type"] = int  # so parse_value() will receive an int
        kwargs.setdefault("metavar", "INT")
        super().__init__(**kwargs)

    def parse_value(self, value: int) -> int:
        if self.min is not None and self.min > value:
            raise argparse.ArgumentError(self, f"{self.metavar} must be equal or greater then {self.min}.")
        if self.max is not None and self.max < value:
            raise argparse.ArgumentError(self, f"{self.metavar} must be equal or smaller then {self.max}.")
        return value


class KeyBackendAction(SingleValueAction[str, KeyBackend[BaseModel, BaseModel, BaseModel]]):
    """Action for configuring the key backend to use for a new certificate authority."""

    def __init__(self, **kwargs: Any) -> None:
        kwargs.setdefault("choices", list(model_settings.CA_KEY_BACKENDS))
        kwargs.setdefault("default", key_backends[model_settings.CA_DEFAULT_KEY_BACKEND])
        super().__init__(**kwargs)

    def parse_value(self, value: str) -> KeyBackend[BaseModel, BaseModel, BaseModel]:
        """Parse the value for this action."""
        return key_backends[value]


class KeySizeAction(SingleValueAction[str, int]):
    """Action for adding a keysize, an integer that must be a power of two (2048, 4096, ...).

    >>> parser = argparse.ArgumentParser()
    >>> parser.add_argument('--size', action=KeySizeAction)  # doctest: +ELLIPSIS
    KeySizeAction(...)
    >>> parser.parse_args(['--size', '4096'])
    Namespace(size=4096)
    """

    def __init__(self, **kwargs: Any) -> None:
        kwargs.setdefault("metavar", "{2048,4096,8192,...}")
        super().__init__(**kwargs)

    def parse_value(self, value: str) -> int:
        """Parse the value for this action."""
        try:
            key_size = int(value)
        except ValueError as ex:
            raise argparse.ArgumentError(self, f"{value}: Must be an integer.") from ex

        try:
            is_power_two_validator(key_size)
        except ValueError as ex:
            raise argparse.ArgumentError(self, str(ex)) from ex

        if key_size < model_settings.CA_MIN_KEY_SIZE:
            raise argparse.ArgumentError(
                self, f"{key_size}: Must be at least {model_settings.CA_MIN_KEY_SIZE} bits."
            )
        return key_size


class MultipleURLAction(argparse.Action):
    """Action for multiple URLs.

    >>> parser = argparse.ArgumentParser()
    >>> parser.add_argument('--url', action=MultipleURLAction)  # doctest: +ELLIPSIS
    MultipleURLAction(...)
    >>> parser.parse_args(['--url', 'https://example.com', '--url', 'https://example.net'])
    Namespace(url=['https://example.com', 'https://example.net'])
    """

    def __init__(self, **kwargs: Any) -> None:
        kwargs.setdefault("default", [])
        kwargs.setdefault("metavar", "URL")
        super().__init__(**kwargs)

    def __call__(  # type: ignore[override] # argparse.Action defines much looser type for values
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str,
        option_string: Optional[str] = None,
    ) -> None:
        validator = URLValidator()
        try:
            validator(values)
        except ValidationError as ex:
            raise argparse.ArgumentError(self, f"{values}: Not a valid URL.") from ex

        getattr(namespace, self.dest).append(values)


class PasswordAction(argparse.Action):
    """Action for adding a password argument.

    If the cli does not pass an argument value, the action prompt the user for a password.

    >>> parser = argparse.ArgumentParser()
    >>> parser.add_argument('--password', action=PasswordAction)  # doctest: +ELLIPSIS
    PasswordAction(...)
    >>> parser.parse_args(['--password', 'secret'])
    Namespace(password=b'secret')
    """

    def __init__(self, prompt: str = "Password: ", **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.prompt = prompt

    def __call__(  # type: ignore[override] # argparse.Action defines much looser type for values
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Optional[str],
        option_string: Optional[str] = None,
    ) -> None:
        if values is None:
            values = getpass.getpass(prompt=self.prompt)

        setattr(namespace, self.dest, values.encode("utf-8"))


class CertificationPracticeStatementAction(argparse.Action):
    """Add a Certification Practice Statement to a previously added Certificate Policy.

    This action works in tandem with :py:class:`~django_ca.management.actions.PolicyIdentifierAction`, and has
    to be called after that action to add a `policy_qualifier` to it. The `dest` arg to this action must
    match the destination of the `PolicyIdentifierAction`.

    The action verifies that the given value is a URI.

    >>> parser = argparse.ArgumentParser()
    >>> parser.add_argument('--pi', action=PolicyIdentifierAction)  # doctest: +ELLIPSIS
    PolicyIdentifierAction(...)
    >>> parser.add_argument(
    ...     '--cps', action=CertificationPracticeStatementAction, dest="pi"
    ... )  # doctest: +ELLIPSIS
    CertificationPracticeStatementAction(...)
    >>> parser.parse_args(['--pi', '1.2.3', '--cps', 'https://example.com/cps']).pi[0].policy_qualifiers
    ['https://example.com/cps']
    """

    def __init__(self, **kwargs: Any) -> None:
        kwargs["metavar"] = "URL"
        super().__init__(**kwargs)

    def __call__(  # type: ignore[override] # argparse.Action defines much looser type for values
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str,
        option_string: Optional[str] = None,
    ) -> None:
        certificate_policies = getattr(namespace, self.dest)
        # Make sure that --policy-identifier was called before
        if certificate_policies is None:
            raise argparse.ArgumentError(self, "Must be preceded by --policy-identifier.")

        # RFC 5280, section 4.2.1.4 mandates that CPS must be in the form of a URI.
        validator = URLValidator()
        try:
            validator(values)
        except ValidationError as ex:
            raise argparse.ArgumentError(self, f"{values}: Not a valid URL.") from ex

        certificate_policies[-1].policy_qualifiers.append(values)


class PolicyIdentifierAction(argparse.Action):
    """Action to add a Certificate Policies extension.

    This action adds a :py:class:`cg:~cryptography.x509.CertificatePolicies` instance to the namespace. A
    :py:class:`cg:~cryptography.x509.PolicyInformation` with the given OID as `policy_identifier` will be
    added to it. Policies given in previous iterations of this argument will be prepended.

    The `allow_any_policy` argument allows adding the ``anyPolicy`` (OID "2.5.29.32.0") policy can be added.
    This is the case for certificate authorities.

    >>> parser = argparse.ArgumentParser()
    >>> parser.add_argument('--pi', action=PolicyIdentifierAction)  # doctest: +ELLIPSIS
    PolicyIdentifierAction(...)
    >>> parser.parse_args(['--pi', '1.2.3']).pi  # doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
    <CertificatePolicies([<PolicyInformation(policy_identifier=<ObjectIdentifier(oid=1.2.3, name=...)>,
            policy_qualifiers=[])>])>
    >>> parser.parse_args(['--pi', '2.5.29', '--pi', '1.2.3']).pi  # doctest: +ELLIPSIS  +NORMALIZE_WHITESPACE
    <CertificatePolicies([<PolicyInformation(policy_identifier=<ObjectIdentifier(oid=2.5.29, name=...)>,
            policy_qualifiers=[])>,
        <PolicyInformation(policy_identifier=<ObjectIdentifier(oid=1.2.3, name=...)>,
            policy_qualifiers=[])>])>
    """

    def __init__(self, **kwargs: Any) -> None:
        self.allow_any_policy = kwargs.pop("allow_any_policy", False)
        kwargs["metavar"] = "OID"
        super().__init__(**kwargs)

    def __call__(  # type: ignore[override] # argparse.Action defines much looser type for values
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str,
        option_string: Optional[str] = None,
    ) -> None:
        if values == "anyPolicy":
            values = "2.5.29.32.0"

        if self.allow_any_policy is False and values == "2.5.29.32.0":
            raise argparse.ArgumentError(self, "anyPolicy is not allowed in this context.")

        try:
            oid = x509.ObjectIdentifier(values)
        except ValueError as ex:
            raise argparse.ArgumentError(self, f"invalid ObjectIdentifier value: '{values}'") from ex

        policy = x509.PolicyInformation(policy_identifier=oid, policy_qualifiers=[])

        if certificate_policies := getattr(namespace, self.dest):
            policies = [*certificate_policies, policy]
        else:
            policies = [policy]

        setattr(namespace, self.dest, x509.CertificatePolicies(policies=policies))


class ReasonAction(SingleValueAction[str, ReasonFlags]):
    """Action to select a revocation reason.

    >>> parser = argparse.ArgumentParser()
    >>> parser.add_argument('--reason', action=ReasonAction)  # doctest: +ELLIPSIS
    ReasonAction(...)
    >>> parser.parse_args(['--reason', 'key_compromise'])
    Namespace(reason=<ReasonFlags.key_compromise: 'keyCompromise'>)
    """

    def __init__(self, **kwargs: Any) -> None:
        kwargs["choices"] = sorted([r.name for r in ReasonFlags])
        kwargs.setdefault("default", ReasonFlags.unspecified)
        super().__init__(**kwargs)

    def parse_value(self, value: str) -> ReasonFlags:
        """Parse the value for this action."""
        # NOTE: set of choices already assures that value is a valid ReasonFlag
        return ReasonFlags[value]


class NameAction(SingleValueAction[str, str]):
    """Action to parse a string into a :py:class:`cg:~cryptography.x509.Name`.

    Note that this action does *not* take care of sorting the subject in any way.

    >>> parser = argparse.ArgumentParser()
    >>> parser.add_argument('--name', action=NameAction)  # doctest: +ELLIPSIS
    NameAction(...)
    >>> parser.parse_args(["--name", "CN=example.com"])
    Namespace(name=CN=example.com)
    """

    def parse_value(self, value: str) -> str:
        # TODO: In django-ca 2.0, parse subject here directly using parse_name_rfc4514().
        try:
            return value
        except ValueError as ex:  # pragma: no cover  # pragma: only django-ca<2.0
            raise argparse.ArgumentError(self, str(ex)) from ex


class URLAction(SingleValueAction[str, str]):
    """Action to pass a single valid URL.

    >>> parser = argparse.ArgumentParser()
    >>> parser.add_argument('--url', action=URLAction)  # doctest: +ELLIPSIS
    URLAction(...)
    >>> parser.parse_args(['--url', 'https://example.com'])
    Namespace(url='https://example.com')
    """

    def parse_value(self, value: str) -> str:
        """Parse the value for this action."""
        validator = URLValidator()
        try:
            validator(value)
        except ValidationError as ex:
            raise argparse.ArgumentError(self, f"{value}: Not a valid URL.") from ex

        return value


class UserNoticeAction(argparse.Action):
    """Add a User Notice to a previously added Certificate Policy.

    This action works in tandem with :py:class:`~django_ca.management.actions.PolicyIdentifierAction`, and has
    to be called after that action to add a `policy_qualifier` to it. The `dest` arg to this action must
    match the destination of the `PolicyIdentifierAction`.

    The action verifies that the given value is no longer then 200 characters (RFC 5280, section 4.2.1.4).

    >>> parser = argparse.ArgumentParser()
    >>> parser.add_argument('--pi', action=PolicyIdentifierAction)  # doctest: +ELLIPSIS
    PolicyIdentifierAction(...)
    >>> parser.add_argument('--notice', action=UserNoticeAction, dest="pi")  # doctest: +ELLIPSIS
    UserNoticeAction(...)
    >>> parser.parse_args(['--pi', '1.2.3', '--notice', 'example text']).pi[0].policy_qualifiers
    [<UserNotice(notice_reference=None, explicit_text='example text')>]
    """

    def __init__(self, **kwargs: Any) -> None:
        kwargs["metavar"] = "TEXT"
        kwargs.setdefault("dest", "certificate_policies")
        super().__init__(**kwargs)

    def __call__(  # type: ignore[override] # argparse.Action defines much looser type for values
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str,
        option_string: Optional[str] = None,
    ) -> None:
        certificate_policies = getattr(namespace, self.dest)
        # Make sure that --policy-identifier was called before
        if certificate_policies is None:
            raise argparse.ArgumentError(self, "Must be preceded by --policy-identifier.")

        # RFC 5280, section 4.2.1.4 mandates that CPS must be in the form of a URI.
        if len(values) > 200:
            raise argparse.ArgumentError(self, f"{self.metavar} must not be longer then 200 characters.")

        user_notice = x509.UserNotice(notice_reference=None, explicit_text=values)

        certificate_policies[-1].policy_qualifiers.append(user_notice)


##########################
# x509 extension actions #
##########################


class CryptographyExtensionAction(argparse.Action, typing.Generic[ExtensionType], metaclass=abc.ABCMeta):
    """Base class for actions that return a cryptography ExtensionType instance."""

    extension_type: type[ExtensionType]


class AlternativeNameLegacyAction(CryptographyExtensionAction[AlternativeNameExtensionType]):
    """Action for AlternativeName extensions."""

    def __init__(self, extension_type: type[AlternativeNameExtensionType], **kwargs: Any) -> None:
        self.extension_type = extension_type
        super().__init__(**kwargs)

    def __call__(  # type: ignore[override] # argparse.Action defines much looser type for values
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str,
        option_string: Optional[str] = None,
    ) -> None:
        ext = getattr(namespace, self.dest)
        if ext is None:
            names = []
        else:
            names = list(ext.value)

        names.append(parse_general_name(values))
        extension_type = self.extension_type(general_names=names)
        critical = EXTENSION_DEFAULT_CRITICAL[self.extension_type.oid]
        extension = x509.Extension(oid=self.extension_type.oid, critical=critical, value=extension_type)

        setattr(namespace, self.dest, extension)


class AlternativeNameAction(CryptographyExtensionAction[AlternativeNameExtensionType]):
    """Action for AlternativeName extensions.

    >>> parser = argparse.ArgumentParser()
    >>> parser.add_argument(
    ...     '--subject-alternative-name',
    ...     action=AlternativeNameAction,
    ...     extension_type=x509.SubjectAlternativeName
    ... )  # doctest: +ELLIPSIS
    AlternativeNameAction(...)
    >>> args = parser.parse_args(['--subject-alternative-name', 'https://example.com'])
    >>> args.subject_alternative_name  # doctest: +NORMALIZE_WHITESPACE
    <SubjectAlternativeName(<GeneralNames([<UniformResourceIdentifier(value='https://example.com')>])>)>
    """

    def __init__(self, extension_type: type[AlternativeNameExtensionType], **kwargs: Any) -> None:
        self.extension_type = extension_type
        kwargs["metavar"] = "NAME"
        super().__init__(**kwargs)

    def __call__(  # type: ignore[override] # argparse.Action defines much looser type for values
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str,
        option_string: Optional[str] = None,
    ) -> None:
        alternative_names = getattr(namespace, self.dest)
        if alternative_names is None:
            names = []
        else:
            names = list(alternative_names)

        names.append(parse_general_name(values))
        extension_type = self.extension_type(general_names=names)

        setattr(namespace, self.dest, extension_type)


class AuthorityInformationAccessAction(CryptographyExtensionAction[x509.AuthorityInformationAccess]):
    """Action for parsing an AuthorityInformationAccess extension.

    This extension has a required parameter `access_method`, which should be the OID that it creates. You
    would usually add two arguments using this action, one for OCSP responders and one for CA issuers, and
    match the `dest` argument to produce one extension:

    >>> from cryptography.x509.oid import AuthorityInformationAccessOID
    >>> parser = argparse.ArgumentParser()
    >>> parser.add_argument(
    ...     "--ocsp-responder",
    ...     action=AuthorityInformationAccessAction,
    ...     access_method=AuthorityInformationAccessOID.OCSP,
    ...     dest="extension"
    ... )  # doctest: +ELLIPSIS
    AuthorityInformationAccessAction(...)
    >>> parser.add_argument(
    ...     "--ca-issuer",
    ...     action=AuthorityInformationAccessAction,
    ...     access_method=AuthorityInformationAccessOID.CA_ISSUERS,
    ...     dest="extension"
    ... )  # doctest: +ELLIPSIS
    AuthorityInformationAccessAction(...)
    >>> parser.parse_args(
    ...     ["--ocsp-responder", "http://ocsp", "--ca-issuer", "http://issuer"]
    ... )  # doctest: +ELLIPSIS
    Namespace(extension=<AuthorityInformationAccess(...)
    """

    def __init__(self, access_method: x509.ObjectIdentifier, **kwargs: Any) -> None:
        self.access_method = access_method
        kwargs["type"] = general_name_type
        kwargs["metavar"] = ("NAME",)
        super().__init__(**kwargs)

    def __call__(  # type: ignore[override] # argparse.Action defines much looser type for values
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: x509.GeneralName,
        option_string: Optional[str] = None,
    ) -> None:
        extension: Optional[x509.AuthorityInformationAccess] = getattr(namespace, self.dest)
        access_description = x509.AccessDescription(access_method=self.access_method, access_location=values)

        if extension is None:
            access_descriptions = [access_description]
        else:
            access_descriptions = [*extension, access_description]

        # Finally sort by OID so that we have more predictable behavior
        access_descriptions = sorted(access_descriptions, key=lambda ad: ad.access_method.dotted_string)

        extension = x509.AuthorityInformationAccess(access_descriptions)

        setattr(namespace, self.dest, extension)


class ExtendedKeyUsageAction(CryptographyExtensionAction[x509.ExtendedKeyUsage]):
    """Action for parsing an ExtendedKeyUsage extension.

    >>> parser = argparse.ArgumentParser()
    >>> parser.add_argument('--extended-key-usage', action=ExtendedKeyUsageAction)  # doctest: +ELLIPSIS
    ExtendedKeyUsageAction(...)
    >>> args = parser.parse_args(["--extended-key-usage", "serverAuth", "clientAuth"])
    >>> args.extended_key_usage  # doctest: +NORMALIZE_WHITESPACE
    <ExtendedKeyUsage([<ObjectIdentifier(oid=1.3.6.1.5.5.7.3.1, name=serverAuth)>,
                                        <ObjectIdentifier(oid=1.3.6.1.5.5.7.3.2, name=clientAuth)>])>
    """

    extension_type = x509.ExtendedKeyUsage

    def __init__(self, **kwargs: Any) -> None:
        kwargs.setdefault("nargs", "+")
        super().__init__(**kwargs)

    def __call__(  # type: ignore[override] # argparse.Action defines much looser type for values
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: list[str],
        option_string: Optional[str] = None,
    ) -> None:
        usages: list[x509.ObjectIdentifier] = []

        for value in values:
            if value in constants.EXTENDED_KEY_USAGE_OIDS:
                oid = constants.EXTENDED_KEY_USAGE_OIDS[value]
            else:
                try:
                    oid = x509.ObjectIdentifier(value)
                except ValueError as ex:
                    raise argparse.ArgumentError(
                        self, f"{value}: Not a dotted string or known Extended Key Usage."
                    ) from ex

            if oid in usages:
                raise argparse.ArgumentError(self, f"{value}: Extended Key Usage is added multiple times.")
            usages.append(oid)

        extended_key_usage = x509.ExtendedKeyUsage(usages)
        setattr(namespace, self.dest, extended_key_usage)


class KeyUsageAction(CryptographyExtensionAction[x509.KeyUsage]):
    """Action for parsing a KeyUsage extension.

    >>> parser = argparse.ArgumentParser()
    >>> parser.add_argument('--key-usage', action=KeyUsageAction)  # doctest: +ELLIPSIS
    KeyUsageAction(...)
    >>> args = parser.parse_args(['--key-usage', 'keyCertSign'])
    >>> args.key_usage  # doctest: +NORMALIZE_WHITESPACE
    <KeyUsage(digital_signature=False,
             content_commitment=False,
             key_encipherment=False,
             data_encipherment=False,
             key_agreement=False,
             key_cert_sign=True,
             crl_sign=False,
             encipher_only=False,
             decipher_only=False)>
    """

    extension_type = x509.KeyUsage

    def __init__(self, **kwargs: Any) -> None:
        # TODO: add choices once support for old comma-separated lists are removed.
        kwargs.setdefault("nargs", "+")
        super().__init__(**kwargs)

    def __call__(  # type: ignore[override] # argparse.Action defines much looser type for values
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: list[str],
        option_string: Optional[str] = None,
    ) -> None:
        if invalid_usages := [ku for ku in values if ku not in KEY_USAGE_NAMES.values()]:
            raise argparse.ArgumentError(
                self, f"{', '.join(sorted(set(invalid_usages)))}: Invalid key usage."
            )

        key_usages: dict[str, bool] = {k: v in values for k, v in KEY_USAGE_NAMES.items()}
        try:
            extension_type = x509.KeyUsage(**key_usages)
        except ValueError as ex:
            raise argparse.ArgumentError(self, str(ex)) from ex

        setattr(namespace, self.dest, extension_type)


class TLSFeatureAction(CryptographyExtensionAction[x509.TLSFeature]):
    """Action for parsing a TLSFeature extension."""

    extension_type = x509.TLSFeature

    def __init__(self, **kwargs: Any) -> None:
        kwargs.setdefault("nargs", "+")
        super().__init__(**kwargs)

    def __call__(  # type: ignore[override] # argparse.Action defines much looser type for values
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: list[str],
        option_string: Optional[str] = None,
    ) -> None:
        try:
            features = [constants.TLS_FEATURE_NAMES[value] for value in values]
        except KeyError as ex:
            raise argparse.ArgumentError(self, f"Unknown TLSFeature: {ex.args[0]}") from ex

        extension_type = x509.TLSFeature(features=features)
        setattr(namespace, self.dest, extension_type)
