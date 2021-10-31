# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca.  If not,
# see <http://www.gnu.org/licenses/>.

"""Collection of argparse actions for django-ca management commands."""

import abc
import argparse
import getpass
import typing
from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding

from django.core.exceptions import ValidationError
from django.core.validators import URLValidator

from .. import ca_settings
from ..constants import ReasonFlags
from ..models import Certificate
from ..models import CertificateAuthority
from ..subject import Subject
from ..utils import is_power2
from ..utils import parse_encoding
from ..utils import parse_hash_algorithm
from ..utils import parse_key_curve
from ..utils import split_str
from ..utils import x509_name

ActionType = typing.TypeVar("ActionType")


class SingleValueAction(argparse.Action, typing.Generic[ActionType], metaclass=abc.ABCMeta):
    """Abstract/generic base class for arguments that take a single value.

    The main purpose of this class is to improve type hinting.
    """

    type: typing.Type[ActionType]

    @abc.abstractmethod
    def parse_value(self, value: str) -> ActionType:
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
        values: str,
        option_string: typing.Optional[str] = None,
    ) -> None:
        setattr(namespace, self.dest, self.parse_value(values))


class AlgorithmAction(SingleValueAction[hashes.HashAlgorithm]):
    """Action for giving an algorithm.

    >>> parser.add_argument('--algorithm', action=AlgorithmAction)  # doctest: +ELLIPSIS
    AlgorithmAction(...)
    >>> parser.parse_args(['--algorithm', 'SHA256'])  # doctest: +ELLIPSIS
    Namespace(algorithm=<cryptography.hazmat.primitives.hashes.SHA256 object at ...>)
    """

    def parse_value(self, value: str) -> hashes.HashAlgorithm:
        """Parse the value for this action."""
        try:
            return parse_hash_algorithm(value)
        except ValueError as e:
            raise argparse.ArgumentError(self, str(e))


class CertificateAction(SingleValueAction[Certificate]):
    """Action for naming a certificate."""

    def __init__(self, allow_revoked: bool = False, **kwargs: typing.Any) -> None:
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


class CertificateAuthorityAction(SingleValueAction[CertificateAuthority]):
    """Action for naming a certificate authority."""

    def __init__(
        self, allow_disabled: bool = False, allow_unusable: bool = False, **kwargs: typing.Any
    ) -> None:
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


class ExpiresAction(SingleValueAction[timedelta]):
    """Action for passing a timedelta in days.

    NOTE: str(timedelta) is different in python 3.6, so only outputting days here

    >>> parser.add_argument('--expires', action=ExpiresAction)  # doctest: +ELLIPSIS
    ExpiresAction(...)
    >>> parser.parse_args(['--expires', '3']).expires.days
    3
    """

    def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        kwargs.setdefault("default", ca_settings.CA_DEFAULT_EXPIRES)
        super().__init__(*args, **kwargs)

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


class FormatAction(SingleValueAction[Encoding]):
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


class KeyCurveAction(SingleValueAction[ec.EllipticCurve]):
    """Action to parse an ECC curve value.

    >>> parser.add_argument('--curve', action=KeyCurveAction)  # doctest: +ELLIPSIS
    KeyCurveAction(...)
    >>> parser.parse_args(['--curve', 'SECP256R1'])  # doctest: +ELLIPSIS
    Namespace(curve=<cryptography.hazmat.primitives.asymmetric.ec.SECP256R1 object at ...>)
    """

    def parse_value(self, value: str) -> ec.EllipticCurve:
        """Parse the value for this action."""
        try:
            return parse_key_curve(value)
        except ValueError as e:
            raise argparse.ArgumentError(self, str(e))


class KeySizeAction(SingleValueAction[int]):
    """Action for adding a keysize, an integer that must be a power of two (2048, 4096, ...).

    >>> parser.add_argument('--size', action=KeySizeAction)  # doctest: +ELLIPSIS
    KeySizeAction(...)
    >>> parser.parse_args(['--size', '4096'])
    Namespace(size=4096)
    """

    def __init__(self, **kwargs: typing.Any) -> None:
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

    def __init__(self, **kwargs: typing.Any) -> None:
        kwargs.setdefault("default", [])
        kwargs.setdefault("metavar", "URL")
        super().__init__(**kwargs)

    def __call__(  # type: ignore[override] # argparse.Action defines much looser type for values
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str,
        option_string: typing.Optional[str] = None,
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

    def __init__(self, prompt: str = "Password: ", **kwargs: typing.Any) -> None:
        super().__init__(**kwargs)
        self.prompt = prompt

    def __call__(  # type: ignore[override] # argparse.Action defines much looser type for values
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: typing.Optional[str],
        option_string: typing.Optional[str] = None,
    ) -> None:
        if values is None:
            values = getpass.getpass(prompt=self.prompt)

        setattr(namespace, self.dest, values.encode("utf-8"))


class ReasonAction(SingleValueAction[ReasonFlags]):
    """Action to select a revocation reason.

    >>> parser.add_argument('--reason', action=ReasonAction)  # doctest: +ELLIPSIS
    ReasonAction(...)
    >>> parser.parse_args(['--reason', 'key_compromise'])
    Namespace(reason=<ReasonFlags.key_compromise: 'keyCompromise'>)
    """

    def __init__(self, **kwargs: typing.Any) -> None:
        kwargs["choices"] = sorted([r.name for r in ReasonFlags])
        kwargs.setdefault("default", ReasonFlags.unspecified)
        super().__init__(**kwargs)

    def parse_value(self, value: str) -> ReasonFlags:
        """Parse the value for this action."""
        # NOTE: set of choices already assures that value is a valid ReasonFlag
        return ReasonFlags[value]


class SubjectAction(SingleValueAction[Subject]):
    """Action for giving a subject.

    >>> parser.add_argument('--subject', action=SubjectAction)  # doctest: +ELLIPSIS
    SubjectAction(...)
    >>> parser.parse_args(['--subject', '/CN=example.com'])
    Namespace(subject=Subject("/CN=example.com"))
    """

    def parse_value(self, value: str) -> Subject:
        """Parse the value for this action."""
        try:
            return Subject(value)
        except ValueError as e:
            raise argparse.ArgumentError(self, str(e))


class NameAction(SingleValueAction[x509.Name]):
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


class URLAction(SingleValueAction[str]):
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


class ExtensionAction(argparse.Action):  # pylint: disable=abstract-method
    """Base class for extension actions.

    Actions using this class as a base class **have** to pass an extra ``extension`` kwarg with a subclass of
    :py:class:`~django_ca.extensions.Extension`.

    The namespace target will always be the extension key regardless of any option string, note how the
    extension is stored in ``key_usage`` and not in ``--ext``, as you would normally expect:

    >>> from django_ca.extensions import KeyUsage
    >>> parser.add_argument('--ext', action=OrderedSetExtensionAction,
    ...                     extension=KeyUsage)  # doctest: +ELLIPSIS
    OrderedSetExtensionAction(...)
    >>> parser.parse_args(['--ext', 'critical,keyCertSign'])
    Namespace(key_usage=<KeyUsage: ['keyCertSign'], critical=True>)
    """

    def __init__(self, **kwargs: typing.Any) -> None:
        self.extension = kwargs.pop("extension")
        kwargs["dest"] = self.extension.key
        super().__init__(**kwargs)


class OrderedSetExtensionAction(ExtensionAction):
    """Action for AlternativeName extensions, e.g. KeyUsage.

    Arguments using this action expect an extra ``extension`` kwarg with a subclass of
    :py:class:`~django_ca.extensions.OrderedSetExtension`.

    >>> from django_ca.extensions import KeyUsage
    >>> parser.add_argument('--ext', action=OrderedSetExtensionAction,
    ...                     extension=KeyUsage)  # doctest: +ELLIPSIS
    OrderedSetExtensionAction(...)
    >>> parser.parse_args(['--ext', 'critical,keyCertSign'])
    Namespace(key_usage=<KeyUsage: ['keyCertSign'], critical=True>)
    """

    def __call__(  # type: ignore[override] # argparse.Action defines much looser type for values
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str,
        option_string: typing.Optional[str] = None,
    ) -> None:
        ext = self.extension()

        ext_values = list(split_str(values, ", "))
        if ext_values[0] == "critical":
            ext_values = ext_values[1:]
            ext.critical = True
        else:
            ext.critical = False

        try:
            ext |= ext_values
        except ValueError as e:
            parser.error(f"Invalid extension value: {values}: {e}")

        setattr(namespace, self.dest, ext)


class AlternativeNameAction(ExtensionAction):
    """Action for AlternativeName extensions.

    Arguments using this action expect an extra ``extension`` kwarg with a subclass of
    :py:class:`~django_ca.extensions.AlternativeNameExtension`.

    >>> from django_ca.extensions import SubjectAlternativeName
    >>> parser.add_argument('--san', action=AlternativeNameAction,
    ...                     extension=SubjectAlternativeName)  # doctest: +ELLIPSIS
    AlternativeNameAction(...)
    >>> parser.parse_args(['--san', 'https://example.com'])
    Namespace(subject_alternative_name=<SubjectAlternativeName: ['URI:https://example.com'], critical=False>)
    """

    def __call__(  # type: ignore[override] # argparse.Action defines much looser type for values
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str,
        option_string: typing.Optional[str] = None,
    ) -> None:
        setattr(namespace, self.dest, self.extension({"value": [values]}))
