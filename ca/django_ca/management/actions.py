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
import warnings
from datetime import timedelta
from typing import Any, List, Optional, Type

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding

from django.core.exceptions import ValidationError
from django.core.validators import URLValidator

from django_ca import ca_settings, constants
from django_ca.constants import EXTENSION_DEFAULT_CRITICAL, EXTENSION_KEYS, KEY_USAGE_NAMES, ReasonFlags
from django_ca.deprecation import RemovedInDjangoCA125Warning, RemovedInDjangoCA126Warning
from django_ca.models import Certificate, CertificateAuthority
from django_ca.typehints import AllowedHashTypes, AlternativeNameExtensionType
from django_ca.utils import (
    is_power2,
    parse_encoding,
    parse_general_name,
    parse_hash_algorithm,
    parse_key_curve,
    x509_name,
)

ActionType = typing.TypeVar("ActionType")  # pylint: disable=invalid-name
ParseType = typing.TypeVar("ParseType")  # pylint: disable=invalid-name
ExtensionType = typing.TypeVar("ExtensionType", bound=x509.ExtensionType)  # pylint: disable=invalid-name


class SingleValueAction(argparse.Action, typing.Generic[ParseType, ActionType], metaclass=abc.ABCMeta):
    """Abstract/generic base class for arguments that take a single value.

    The main purpose of this class is to improve type hinting.
    """

    type: Type[ActionType]

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

    >>> parser.add_argument('--algorithm', action=AlgorithmAction)  # doctest: +ELLIPSIS
    AlgorithmAction(...)
    >>> parser.parse_args(['--algorithm', 'SHA-256'])  # doctest: +ELLIPSIS
    Namespace(algorithm=<cryptography.hazmat.primitives.hashes.SHA256 object at ...>)
    """

    def __init__(self, **kwargs: Any) -> None:
        kwargs.setdefault("metavar", "{SHA-512,SHA-256,...}")
        # Enable this line once support for non-standard names is dropped
        # kwargs.setdefault("choices", sorted(constants.HASH_ALGORITHM_TYPES))
        super().__init__(**kwargs)

    def parse_value(self, value: str) -> AllowedHashTypes:
        """Parse the value for this action."""
        try:
            return constants.HASH_ALGORITHM_TYPES[value]()
        except KeyError:
            # NOTE: when removing, add the choices option above
            try:
                parsed = parse_hash_algorithm(value)
                warnings.warn(
                    f"{value}: Support for non-standard algorithm names will be dropped in django-ca 1.25.0.",
                    RemovedInDjangoCA125Warning,
                )
                return parsed
            except ValueError as ex:
                raise argparse.ArgumentError(self, str(ex)) from ex


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

    def __init__(self, allow_disabled: bool = False, allow_unusable: bool = False, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.allow_disabled = allow_disabled
        self.allow_unusable = allow_unusable

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

        # verify that the private key exists
        if not self.allow_unusable and not ca.key_exists:
            raise argparse.ArgumentError(self, f"{ca}: {ca.private_key_path}: Private key does not exist.")

        return ca


class ExpiresAction(SingleValueAction[str, timedelta]):
    """Action for passing a timedelta in days.

    NOTE: str(timedelta) is different in python 3.6, so only outputting days here

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

    >>> parser.add_argument('--format', action=FormatAction)  # doctest: +ELLIPSIS
    FormatAction(...)
    >>> parser.parse_args(['--format', 'DER'])
    Namespace(format=<Encoding.DER: 'DER'>)
    """

    def parse_value(self, value: str) -> Encoding:
        """Parse the value for this action."""
        try:
            return parse_encoding(value)
        except ValueError as e:
            raise argparse.ArgumentError(self, str(e))


class EllipticCurveAction(SingleValueAction[str, ec.EllipticCurve]):
    """Action to parse an elliptic curve value.

    >>> parser.add_argument('--elliptic-curve', action=EllipticCurveAction)  # doctest: +ELLIPSIS
    EllipticCurveAction(...)
    >>> parser.parse_args(['--elliptic-curve', 'secp256r1'])  # doctest: +ELLIPSIS
    Namespace(elliptic_curve=<cryptography.hazmat.primitives.asymmetric.ec.SECP256R1 object at ...>)
    """

    def __init__(self, **kwargs: Any) -> None:
        kwargs.setdefault("metavar", "{secp256r1,secp384r1,secp521r1,...}")
        # Enable this line once support for non-standard names is dropped
        # kwargs.setdefault("choices", list(constants.ELLIPTIC_CURVE_TYPES))
        super().__init__(**kwargs)

    def parse_value(self, value: str) -> ec.EllipticCurve:
        """Parse the value for this action."""
        msg = f"{value}: Support for non-standard elliptic curve names will be dropped in django-ca 1.25.0."
        try:
            return constants.ELLIPTIC_CURVE_TYPES[value]()
        except KeyError:
            # NOTE: when removing, add the choices option above
            try:
                parsed = parse_key_curve(value)
                warnings.warn(msg, RemovedInDjangoCA125Warning)
                return parsed
            except ValueError as e:
                raise argparse.ArgumentError(self, str(e))


class IntegerRangeAction(SingleValueAction[int, int]):
    """An int action with an optional min/max value.

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


class KeySizeAction(SingleValueAction[str, int]):
    """Action for adding a keysize, an integer that must be a power of two (2048, 4096, ...).

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

        if not is_power2(key_size):
            raise argparse.ArgumentError(self, f"{key_size}: Must be a power of two (2048, 4096, ...).")

        if key_size < ca_settings.CA_MIN_KEY_SIZE:
            raise argparse.ArgumentError(
                self, f"{key_size}: Must be at least {ca_settings.CA_MIN_KEY_SIZE} bits."
            )
        return key_size


class MultipleURLAction(argparse.Action):
    """Action for multiple URLs.

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
        except ValidationError:
            parser.error(f"{values}: Not a valid URL.")

        getattr(namespace, self.dest).append(values)


class PasswordAction(argparse.Action):
    """Action for adding a password argument.

    If the cli does not pass an argument value, the action prompt the user for a password.

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


class ReasonAction(SingleValueAction[str, ReasonFlags]):
    """Action to select a revocation reason.

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


class NameAction(SingleValueAction[str, x509.Name]):
    """Action to parse a string into a :py:class:`cg:~cryptography.x509.Name`.

    Note that this action does *not* take care of sorting the subject in any way.

    >>> parser.add_argument('--name', action=NameAction)  # doctest: +ELLIPSIS
    NameAction(...)
    >>> parser.parse_args(["--name", "/CN=example.com"])
    Namespace(name=<Name(CN=example.com)>)
    """

    def parse_value(self, value: str) -> x509.Name:
        try:
            return x509_name(value)
        except ValueError as e:
            raise argparse.ArgumentError(self, str(e))


class URLAction(SingleValueAction[str, str]):
    """Action to pass a single valid URL.

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


##########################
# x509 extension actions #
##########################


class CryptographyExtensionAction(argparse.Action, typing.Generic[ExtensionType], metaclass=abc.ABCMeta):
    """Base class for actions that return a cryptography ExtensionType instance."""

    extension_type: Type[ExtensionType]

    def __init__(self, **kwargs: Any) -> None:
        kwargs["dest"] = EXTENSION_KEYS[self.extension_type.oid]
        super().__init__(**kwargs)


class AlternativeNameAction(CryptographyExtensionAction[AlternativeNameExtensionType]):
    """Action for AlternativeName extensions.

    >>> parser.add_argument('--san', action=AlternativeNameAction,
    ...                     extension_type=x509.SubjectAlternativeName)  # doctest: +ELLIPSIS
    AlternativeNameAction(...)
    >>> args = parser.parse_args(['--san', 'https://example.com'])
    >>> args.subject_alternative_name  # doctest: +NORMALIZE_WHITESPACE
    <Extension(oid=<ObjectIdentifier(oid=2.5.29.17, name=subjectAltName)>,
               critical=False,
               value=<SubjectAlternativeName(<GeneralNames([<UniformResourceIdentifier(value='https://example.com')>])>)>)>
    """

    def __init__(self, extension_type: Type[AlternativeNameExtensionType], **kwargs: Any) -> None:
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


class ExtendedKeyUsageAction(CryptographyExtensionAction[x509.ExtendedKeyUsage]):
    """Action for parsing an ExtendedKeyUsage extension.

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
        values: List[str],
        option_string: Optional[str] = None,
    ) -> None:
        usages: List[x509.ObjectIdentifier] = []

        # Parse legacy format
        if len(values) == 1 and "," in values[0]:
            values = values[0].split(",")
            warnings.warn(
                "Passing a coma-separated list is deprecated, pass space-separated values instead.",
                RemovedInDjangoCA126Warning,
            )

            if values[0] == "critical":
                warnings.warn(
                    "Using critical as first value is deprecated. The extension is critical by default.",
                    RemovedInDjangoCA126Warning,
                )
                values = values[1:]

        for value in values:
            if value in constants.EXTENDED_KEY_USAGE_OIDS:
                oid = constants.EXTENDED_KEY_USAGE_OIDS[value]
            else:
                try:
                    oid = x509.ObjectIdentifier(value)
                except ValueError:
                    parser.error(f"{value}: Not a dotted string or known Extended Key Usage.")

            if oid in usages:
                parser.error(f"{value}: Extended Key Usage is added multiple times.")
            usages.append(oid)

        extended_key_usage = x509.ExtendedKeyUsage(usages)
        setattr(namespace, self.dest, extended_key_usage)


class KeyUsageAction(CryptographyExtensionAction[x509.KeyUsage]):
    """Action for parsing a KeyUsage extension.

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
        kwargs.setdefault("nargs", "+")
        super().__init__(**kwargs)

    def __call__(  # type: ignore[override] # argparse.Action defines much looser type for values
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: List[str],
        option_string: Optional[str] = None,
    ) -> None:
        # Parse legacy format
        if len(values) == 1 and "," in values[0]:
            values = values[0].split(",")
            warnings.warn(
                "Passing a coma-separated list is deprecated, pass space-separated values instead.",
                RemovedInDjangoCA126Warning,
            )

            if values[0] == "critical":
                warnings.warn(
                    "Using critical as first value is deprecated. The extension is critical by default.",
                    RemovedInDjangoCA126Warning,
                )
                values = values[1:]

        if invalid_usages := [ku for ku in values if ku not in KEY_USAGE_NAMES.values()]:
            parser.error(f"{', '.join(sorted(set(invalid_usages)))}: Invalid key usage.")

        key_usages = {k: v in values for k, v in KEY_USAGE_NAMES.items()}
        try:
            extension_type = x509.KeyUsage(**key_usages)
        except ValueError as ex:
            parser.error(str(ex))

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
        values: List[str],
        option_string: Optional[str] = None,
    ) -> None:
        # Parse legacy format
        if len(values) == 1 and "," in values[0]:
            values = values[0].split(",")
            warnings.warn(
                "Passing a coma-separated list is deprecated, pass space-separated values instead.",
                RemovedInDjangoCA126Warning,
            )

            if values[0] == "critical":
                warnings.warn(
                    "Using critical as first value is deprecated. The extension is critical by default.",
                    RemovedInDjangoCA126Warning,
                )
                values = values[1:]

        if "OCSPMustStaple" in values or "MultipleCertStatusRequest" in values:
            warnings.warn(
                "OCSPMustStaple and MultipleCertStatusRequest are deprecated aliases for status_request and "
                "status_request_v2.",
                RemovedInDjangoCA126Warning,
            )

        try:
            features = [constants.TLS_FEATURE_NAMES[value] for value in values]
        except KeyError as ex:
            parser.error(f"Unknown TLSFeature: {ex.args[0]}")

        extension_type = x509.TLSFeature(features=features)
        setattr(namespace, self.dest, extension_type)
