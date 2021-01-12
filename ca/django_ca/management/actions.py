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

import argparse
import getpass
from datetime import timedelta

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
from ..utils import shlex_split


def _parse_timedelta(value):
    # NOTE: Making this a member of ExpiresAction causes an infinite loop for some reason
    try:
        value = int(value)
    except ValueError as ex:
        raise argparse.ArgumentTypeError('Value must be an integer: "%s"' % value) from ex
    if value <= 0:
        raise argparse.ArgumentTypeError('Value must not be negative.')

    return timedelta(days=value)


class AlgorithmAction(argparse.Action):
    """Action for giving an algorithm.

    >>> parser.add_argument('--algorithm', action=AlgorithmAction)  # doctest: +ELLIPSIS
    AlgorithmAction(...)
    >>> parser.parse_args(['--algorithm', 'SHA256'])  # doctest: +ELLIPSIS
    Namespace(algorithm=<cryptography.hazmat.primitives.hashes.SHA256 object at ...>)
    """

    def __call__(self, parser, namespace, value, option_string=None):
        try:
            value = parse_hash_algorithm(value)
        except ValueError as e:
            parser.error(str(e))

        setattr(namespace, self.dest, value)


class CertificateAction(argparse.Action):
    """Action for naming a certificate."""

    def __init__(self, allow_revoked=False, **kwargs):
        super().__init__(**kwargs)
        self.allow_revoked = allow_revoked

    def __call__(self, parser, namespace, value, option_string=None):
        queryset = Certificate.objects.all()
        if self.allow_revoked is False:
            queryset = queryset.filter(revoked=False)

        try:
            setattr(namespace, self.dest, queryset.get_by_serial_or_cn(value))
        except Certificate.DoesNotExist as ex:
            raise parser.error('%s: Certificate not found.' % value) from ex
        except Certificate.MultipleObjectsReturned as ex:
            raise parser.error('%s: Multiple certificates match.' % value) from ex


class CertificateAuthorityAction(argparse.Action):
    """Action for naming a certificate authority."""

    def __init__(self, allow_disabled=False, allow_unusable=False, **kwargs):
        super().__init__(**kwargs)
        self.allow_disabled = allow_disabled
        self.allow_unusable = allow_unusable

    def __call__(self, parser, namespace, value, option_string=None):
        qs = CertificateAuthority.objects.all()
        if self.allow_disabled is False:
            qs = qs.enabled()

        try:
            value = qs.get_by_serial_or_cn(value)
        except CertificateAuthority.DoesNotExist:
            parser.error('%s: Certificate authority not found.' % value)
        except CertificateAuthority.MultipleObjectsReturned:
            parser.error('%s: Multiple Certificate authorities match.' % value)

        # verify that the private key exists
        if not self.allow_unusable and not value.key_exists:
            parser.error('%s: %s: Private key does not exist.' % (value, value.private_key_path))

        setattr(namespace, self.dest, value)


class ExpiresAction(argparse.Action):
    """Action for passing a timedelta in days.

    NOTE: str(timedelta) is different in python 3.6, so only outputting days here

    >>> parser.add_argument('--expires', action=ExpiresAction)  # doctest: +ELLIPSIS
    ExpiresAction(...)
    >>> parser.parse_args(['--expires', '3']).expires.days
    3
    """

    def __init__(self, *args, **kwargs):
        kwargs['type'] = _parse_timedelta
        kwargs.setdefault('default', ca_settings.CA_DEFAULT_EXPIRES)
        super().__init__(*args, **kwargs)

    def __call__(self, parser, namespace, value, option_string=None):
        setattr(namespace, self.dest, value)


class FormatAction(argparse.Action):
    """Action for giving an encoding (DER/PEM).

    >>> parser.add_argument('--format', action=FormatAction)  # doctest: +ELLIPSIS
    FormatAction(...)
    >>> parser.parse_args(['--format', 'DER'])
    Namespace(format=<Encoding.DER: 'DER'>)
    """

    def __call__(self, parser, namespace, value, option_string=None):
        try:
            value = parse_encoding(value)
        except ValueError as e:
            parser.error(str(e))

        setattr(namespace, self.dest, value)


class KeyCurveAction(argparse.Action):
    """Action to parse an ECC curve value.

    >>> parser.add_argument('--curve', action=KeyCurveAction)  # doctest: +ELLIPSIS
    KeyCurveAction(...)
    >>> parser.parse_args(['--curve', 'SECP256R1'])  # doctest: +ELLIPSIS
    Namespace(curve=<cryptography.hazmat.primitives.asymmetric.ec.SECP256R1 object at ...>)
    """

    def __call__(self, parser, namespace, value, option_string=None):

        try:
            curve = parse_key_curve(value)
        except ValueError as e:
            parser.error(e)
        setattr(namespace, self.dest, curve)


class KeySizeAction(argparse.Action):
    """Action for adding a keysize, an integer that must be a power of two (2048, 4096, ...).

    >>> parser.add_argument('--size', action=KeySizeAction)  # doctest: +ELLIPSIS
    KeySizeAction(...)
    >>> parser.parse_args(['--size', '4096'])
    Namespace(size=4096)
    """

    metavar = '{2048,4096,8192,...}'

    def __init__(self, **kwargs):
        kwargs.setdefault('type', int)
        kwargs.setdefault('metavar', self.metavar)
        super().__init__(**kwargs)

    def __call__(self, parser, namespace, value, option_string=None):
        option_string = option_string or 'key size'

        if not is_power2(value):
            parser.error('%s must be a power of two (2048, 4096, ...)' % option_string)
        elif value < ca_settings.CA_MIN_KEY_SIZE:
            parser.error('%s must be at least %s bits.'
                         % (option_string, ca_settings.CA_MIN_KEY_SIZE))
        setattr(namespace, self.dest, value)


class MultipleURLAction(argparse.Action):
    """Action for multiple URLs.

    >>> parser.add_argument('--url', action=MultipleURLAction)  # doctest: +ELLIPSIS
    MultipleURLAction(...)
    >>> parser.parse_args(['--url', 'https://example.com', '--url', 'https://example.net'])
    Namespace(url=['https://example.com', 'https://example.net'])
    """

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('default', [])
        kwargs.setdefault('metavar', 'URL')
        super().__init__(*args, **kwargs)

    def __call__(self, parser, namespace, value, option_string=None):
        validator = URLValidator()
        try:
            validator(value)
        except ValidationError:
            parser.error('%s: Not a valid URL.' % value)

        getattr(namespace, self.dest).append(value)


class PasswordAction(argparse.Action):
    """Action for adding a password argument.

    If the cli does not pass an argument value, the action prompt the user for a password.

    >>> parser.add_argument('--password', action=PasswordAction)  # doctest: +ELLIPSIS
    PasswordAction(...)
    >>> parser.parse_args(['--password', 'secret'])
    Namespace(password=b'secret')
    """

    def __init__(self, prompt=None, **kwargs):
        super().__init__(**kwargs)
        self.prompt = prompt

    def __call__(self, parser, namespace, value, option_string=None):
        if value is None:
            kwargs = {}
            if self.prompt:
                kwargs['prompt'] = self.prompt
            value = getpass.getpass(**kwargs)

        setattr(namespace, self.dest, value.encode('utf-8'))


class ReasonAction(argparse.Action):
    """Action to select a revocation reason.

    >>> parser.add_argument('--reason', action=ReasonAction)  # doctest: +ELLIPSIS
    ReasonAction(...)
    >>> parser.parse_args(['--reason', 'key_compromise'])
    Namespace(reason=<ReasonFlags.key_compromise: 'keyCompromise'>)
    """

    def __init__(self, *args, **kwargs):
        kwargs['choices'] = sorted([r.name for r in ReasonFlags])
        super().__init__(*args, **kwargs)

    def __call__(self, parser, namespace, value, option_string=None):
        # NOTE: set of choices already assures that value is a valid ReasonFlag
        setattr(namespace, self.dest, ReasonFlags[value])


class SubjectAction(argparse.Action):
    """Action for giving a subject.

    >>> parser.add_argument('--subject', action=SubjectAction)  # doctest: +ELLIPSIS
    SubjectAction(...)
    >>> parser.parse_args(['--subject', '/CN=example.com'])
    Namespace(subject=Subject("/CN=example.com"))
    """

    def __call__(self, parser, namespace, value, option_string=None):
        try:
            value = Subject(value)
        except ValueError as e:
            parser.error(e)
        setattr(namespace, self.dest, value)


class URLAction(argparse.Action):
    """Action to pass a single valid URL.

    >>> parser.add_argument('--url', action=URLAction)  # doctest: +ELLIPSIS
    URLAction(...)
    >>> parser.parse_args(['--url', 'https://example.com'])
    Namespace(url='https://example.com')
    """

    def __call__(self, parser, namespace, value, option_string=None):
        validator = URLValidator()
        try:
            validator(value)
        except ValidationError:
            parser.error('%s: Not a valid URL.' % value)
        setattr(namespace, self.dest, value)


##########################
# x509 extension actions #
##########################


class ExtensionAction(argparse.Action):  # pylint: disable=abstract-method,too-few-public-methods
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

    def __init__(self, *args, **kwargs):
        self.extension = kwargs.pop('extension')
        kwargs['dest'] = self.extension.key
        super().__init__(*args, **kwargs)


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

    def __call__(self, parser, namespace, value, option_string=None):
        ext = self.extension()

        values = shlex_split(value, ', ')
        if values[0] == 'critical':
            values = values[1:]
            ext.critical = True
        else:
            ext.critical = False

        try:
            ext |= values
        except ValueError as e:
            parser.error('Invalid extension value: %s: %s' % (value, e))

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

    def __call__(self, parser, namespace, value, option_string=None):
        setattr(namespace, self.dest, self.extension({'value': [value]}))
