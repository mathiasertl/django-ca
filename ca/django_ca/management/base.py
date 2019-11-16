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

import argparse
import getpass
import sys
from datetime import timedelta
from textwrap import indent

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from django.core.management.base import BaseCommand as _BaseCommand
from django.core.management.base import CommandError
from django.core.management.base import OutputWrapper
from django.core.management.color import no_style
from django.core.validators import URLValidator
from django.utils import timezone
from django.utils.encoding import force_bytes

from .. import ca_settings
from ..constants import ReasonFlags
from ..extensions import ExtendedKeyUsage
from ..extensions import Extension
from ..extensions import IssuerAlternativeName
from ..extensions import KeyUsage
from ..extensions import NullExtension
from ..extensions import SubjectAlternativeName
from ..extensions import TLSFeature
from ..models import Certificate
from ..models import CertificateAuthority
from ..subject import Subject
from ..utils import SUBJECT_FIELDS
from ..utils import add_colons
from ..utils import is_power2
from ..utils import parse_encoding
from ..utils import parse_hash_algorithm
from ..utils import parse_key_curve
from ..utils import shlex_split


class SubjectAction(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        try:
            value = Subject(value)
        except ValueError as e:
            parser.error(e)
        setattr(namespace, self.dest, value)


class FormatAction(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        try:
            value = parse_encoding(value)
        except ValueError as e:
            parser.error(str(e))

        setattr(namespace, self.dest, value)


class AlgorithmAction(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        try:
            value = parse_hash_algorithm(value)
        except ValueError as e:
            parser.error(str(e))

        setattr(namespace, self.dest, value)


class KeyCurveAction(argparse.Action):
    """Action to parse an ECC curve value."""

    def __call__(self, parser, namespace, value, option_string=None):

        try:
            curve = parse_key_curve(value)
        except ValueError as e:
            parser.error(e)
        setattr(namespace, self.dest, curve)


class KeySizeAction(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        option_string = option_string or 'key size'

        if not is_power2(value):
            parser.error('%s must be a power of two (2048, 4096, ...)' % option_string)
        elif value < ca_settings.CA_MIN_KEY_SIZE:
            parser.error('%s must be at least %s bits.'
                         % (option_string, ca_settings.CA_MIN_KEY_SIZE))
        setattr(namespace, self.dest, value)


class PasswordAction(argparse.Action):
    def __init__(self, prompt=None, **kwargs):
        super(PasswordAction, self).__init__(**kwargs)
        self.prompt = prompt

    def __call__(self, parser, namespace, value, option_string=None):
        if value is None:
            kwargs = {}
            if self.prompt:
                kwargs['prompt'] = self.prompt
            value = getpass.getpass(**kwargs)

        setattr(namespace, self.dest, value.encode('utf-8'))


class CertificateAction(argparse.Action):
    def __init__(self, allow_revoked=False, **kwargs):
        super(CertificateAction, self).__init__(**kwargs)
        self.allow_revoked = allow_revoked

    def __call__(self, parser, namespace, value, option_string=None):
        queryset = Certificate.objects.all()
        if self.allow_revoked is False:
            queryset = queryset.filter(revoked=False)

        try:
            setattr(namespace, self.dest, queryset.get_by_serial_or_cn(value))
        except Certificate.DoesNotExist:
            raise parser.error('%s: Certificate not found.' % value)
        except Certificate.MultipleObjectsReturned:
            raise parser.error('%s: Multiple certificates match.' % value)


class CertificateAuthorityAction(argparse.Action):
    def __init__(self, allow_disabled=False, allow_unusable=False, **kwargs):
        super(CertificateAuthorityAction, self).__init__(**kwargs)
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


class URLAction(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        validator = URLValidator()
        try:
            validator(value)
        except Exception:
            parser.error('%s: Not a valid URL.' % value)
        setattr(namespace, self.dest, value)


def parse_timedelta(value):
    try:
        value = int(value)
    except Exception:
        raise argparse.ArgumentTypeError('Value must be an integer: "%s"' % value)
    if value <= 0:
        raise argparse.ArgumentTypeError('Value must not be negative.')

    return timedelta(days=value)


class ExpiresAction(argparse.Action):
    def __init__(self, *args, **kwargs):
        kwargs['type'] = parse_timedelta
        kwargs.setdefault('default', ca_settings.CA_DEFAULT_EXPIRES)
        super(ExpiresAction, self).__init__(*args, **kwargs)

    def __call__(self, parser, namespace, value, option_string=None):
        setattr(namespace, self.dest, value)


class MultipleURLAction(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        validator = URLValidator()
        try:
            validator(value)
        except Exception:
            parser.error('%s: Not a valid URL.' % value)

        if getattr(namespace, self.dest) is None:
            setattr(namespace, self.dest, [])

        getattr(namespace, self.dest).append(value)


class ExtensionAction(argparse.Action):
    def __init__(self, *args, **kwargs):
        self.extension = kwargs.pop('extension')
        kwargs['dest'] = self.extension.key
        super(ExtensionAction, self).__init__(*args, **kwargs)


class OrderedSetExtensionAction(ExtensionAction):
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
    def __call__(self, parser, namespace, value, option_string=None):
        setattr(namespace, self.dest, self.extension({'value': [value]}))


class ReasonAction(argparse.Action):
    def __init__(self, *args, **kwargs):
        kwargs['choices'] = sorted([r.name for r in ReasonFlags])
        super(ReasonAction, self).__init__(*args, **kwargs)

    def __call__(self, parser, namespace, value, option_string=None):
        # NOTE: set of choices already assures that value is a valid ReasonFlag
        setattr(namespace, self.dest, ReasonFlags[value])


class BinaryOutputWrapper(OutputWrapper):
    def __init__(self, out, ending=b'\n'):
        super(BinaryOutputWrapper, self).__init__(out, ending=ending)

    def write(self, msg, style_func=None, ending=None):
        ending = self.ending if ending is None else ending
        msg = force_bytes(msg)

        if ending and not msg.endswith(ending):
            msg += ending
        self._out.write(msg)


class BaseCommand(_BaseCommand):
    binary_output = False

    def __init__(self, stdout=None, stderr=None, no_color=False):
        if self.binary_output is True:
            self.stdout = BinaryOutputWrapper(stdout or sys.stdout.buffer)
            self.stderr = BinaryOutputWrapper(stderr or sys.stderr.buffer)
            self.style = no_style()
        else:
            super(BaseCommand, self).__init__(stdout, stderr, no_color=no_color)

    def execute(self, *args, **options):
        if self.binary_output is True:
            if options.get('stdout'):  # pragma: no branch
                self.stdout = BinaryOutputWrapper(options.pop('stdout'))
            if options.get('stderr'):  # pragma: no branch
                self.stderr = BinaryOutputWrapper(options.pop('stderr'))
            options['no_color'] = True

        super(BaseCommand, self).execute(*args, **options)

    def add_algorithm(self, parser):
        """Add the --algorithm option."""

        help = 'The HashAlgorithm that will be used to generate the signature (default: %(default)s).' % {
            'default': ca_settings.CA_DIGEST_ALGORITHM.name, }

        parser.add_argument(
            '--algorithm', metavar='{sha512,sha256,...}', default=ca_settings.CA_DIGEST_ALGORITHM,
            action=AlgorithmAction, help=help)

    @property
    def valid_subject_keys(self):
        fields = ['"%s"' % f for f in SUBJECT_FIELDS]
        return '%s and %s' % (', '.join(fields[:-1]), fields[-1])

    def add_subject(self, parser, arg='subject', metavar=None, help=None):
        parser.add_argument(arg, action=SubjectAction, metavar=metavar, help=help)

    def add_ca(self, parser, arg='--ca',
               help='Certificate authority to use (default: %(default)s).',
               allow_disabled=False, no_default=False, allow_unusable=False):
        if no_default is True:
            default = None
        else:
            default = CertificateAuthority.objects.enabled().first()

        help = help % {'default': add_colons(default.serial) if default else None}
        parser.add_argument('%s' % arg, metavar='SERIAL', help=help, default=default,
                            allow_disabled=allow_disabled, allow_unusable=allow_unusable,
                            action=CertificateAuthorityAction)

    def add_ecc_curve(self, parser):
        curve_help = 'Elliptic Curve used for ECC keys (default: %(default)s).' % {
            'default': ca_settings.CA_DEFAULT_ECC_CURVE.__class__.__name__,
        }
        parser.add_argument('--ecc-curve', metavar='CURVE', action=KeyCurveAction,
                            default=ca_settings.CA_DEFAULT_ECC_CURVE,
                            help=curve_help)

    def add_format(self, parser, default=Encoding.PEM, help_text=None, opts=None):
        """Add the --format option."""

        if opts is None:
            opts = ['-f', '--format']
        if help_text is None:
            help_text = 'The format to use ("ASN1" is an alias for "DER", default: %(default)s).'
        help_text = help_text % {'default': default.name}
        parser.add_argument(*opts, metavar='{PEM,ASN1,DER}', default=default,
                            action=FormatAction, help=help_text)

    def add_key_size(self, parser):
        parser.add_argument(
            '--key-size', type=int, action=KeySizeAction, default=ca_settings.CA_DEFAULT_KEY_SIZE,
            metavar='{2048,4096,8192,...}',
            help="Key size for the private key (default: %(default)s).")

    def add_key_type(self, parser):
        parser.add_argument(
            '--key-type', choices=['RSA', 'DSA', 'ECC'], default='RSA',
            help="Key type for the private key (default: %(default)s).")

    def add_password(self, parser, help=None):
        if help is None:
            help = 'Password used for accessing the private key of the CA.'
        parser.add_argument('-p', '--password', nargs='?', action=PasswordAction, help=help)

    def add_profile(self, parser, help_text):
        group = parser.add_argument_group('profiles', help_text)
        group = group.add_mutually_exclusive_group()
        for name, profile in ca_settings.CA_PROFILES.items():
            group.add_argument('--%s' % name, action='store_const', const=name, dest='profile',
                               help=profile.get('description', ''))

    def indent(self, s, prefix='    '):
        return indent(s, prefix)

    def print_extension(self, ext):
        if isinstance(ext, Extension):
            if isinstance(ext, NullExtension):
                if ext.critical:
                    # NOTE: Only PrecertPoison is ever marked as critical
                    self.stdout.write('%s (critical): Yes' % ext.name)
                else:
                    self.stdout.write('%s: Yes' % ext.name)
            else:
                if ext.critical:
                    self.stdout.write('%s (critical):' % ext.name)
                else:
                    self.stdout.write('%s:' % ext.name)

                self.stdout.write(self.indent(ext.as_text()))
        elif isinstance(ext, x509.Extension):
            if ext.critical:  # pragma: no cover - all unrecognized extensions that we have are non-critical
                self.stdout.write('%s (critical): %s' % (ext.oid._name, ext.oid.dotted_string))
            else:
                self.stdout.write('%s: %s' % (ext.oid._name, ext.oid.dotted_string))
        else:  # pragma: no cover
            raise ValueError('Received unknown extension type: %s' % type(ext))

    def print_extensions(self, cert):
        for ext in cert.extensions:
            self.print_extension(ext)

    def test_private_key(self, ca, password):
        try:
            ca.key(password)
        except Exception as e:
            raise CommandError(str(e))


class BaseSignCommand(BaseCommand):
    sign_extensions = {
        SubjectAlternativeName,
        KeyUsage,
        ExtendedKeyUsage,
        TLSFeature,
    }

    def add_base_args(self, parser, no_default_ca=False):
        self.add_subject_group(parser)
        self.add_algorithm(parser)
        self.add_ca(parser, no_default=no_default_ca)
        self.add_password(parser)
        self.add_extensions(parser)

        parser.add_argument(
            '--expires', default=ca_settings.CA_DEFAULT_EXPIRES, action=ExpiresAction,
            help='Sign the certificate for DAYS days (default: %(default)s)')
        parser.add_argument(
            '--alt', metavar='DOMAIN', action=AlternativeNameAction, extension=SubjectAlternativeName,
            help='Add a subjectAltName to the certificate (may be given multiple times)')
        parser.add_argument(
            '--watch', metavar='EMAIL', action='append', default=[],
            help='Email EMAIL when this certificate expires (may be given multiple times)')
        parser.add_argument(
            '--out', metavar='FILE',
            help='Save signed certificate to FILE. If omitted, print to stdout.')

    def add_subject_group(self, parser):
        group = parser.add_argument_group('Certificate subject', self.subject_help)

        # NOTE: We do not set the default argument here because that would mask the user not
        # setting anything at all.
        self.add_subject(
            group, arg='--subject', metavar='/key1=value1/key2=value2/...',
            help='''Valid keys are %s. Pass an empty value (e.g. "/C=/ST=...") to remove a field
                 from the subject.''' % self.valid_subject_keys)

    def add_extensions(self, parser):
        group = parser.add_argument_group('X509 v3 certificate extensions', self.add_extensions_help)
        group.add_argument(
            '--key-usage', metavar='VALUES', action=OrderedSetExtensionAction, extension=KeyUsage,
            help='The keyUsage extension, e.g. "critical,keyCertSign".')
        group.add_argument(
            '--ext-key-usage', metavar='VALUES', action=OrderedSetExtensionAction, extension=ExtendedKeyUsage,
            help='The extendedKeyUsage extension, e.g. "serverAuth,clientAuth".')
        group.add_argument(
            '--tls-feature', metavar='VALUES', action=OrderedSetExtensionAction, extension=TLSFeature,
            help='TLS Feature extensions.')

    def test_options(self, *args, **options):
        ca = options['ca']
        if ca.expires < timezone.now() + options['expires']:
            max_days = (ca.expires - timezone.now()).days
            raise CommandError(
                'Certificate would outlive CA, maximum expiry for this CA is %s days.' % max_days)

        # See if we can work with the private key
        self.test_private_key(ca, options['password'])


class CertCommand(BaseCommand):
    allow_revoked = False

    def add_arguments(self, parser):
        parser.add_argument(
            'cert', action=CertificateAction, allow_revoked=self.allow_revoked,
            help='''Certificate by CommonName or serial. If you give a CommonName (which is not by
                definition unique) there must be only one valid certificate with the given
                CommonName.''')
        super(CertCommand, self).add_arguments(parser)


class CertificateAuthorityDetailMixin(object):
    def add_ca_args(self, parser):
        group = parser.add_argument_group(
            'X509 v3 certificate extensions for signed certificates',
            'Extensions added when signing certificates.')
        group.add_argument('--issuer-url', metavar='URL', action=URLAction,
                           help='URL to the certificate of your CA (in DER format).')
        group.add_argument(
            '--issuer-alt-name', metavar='URL', action=ExtensionAction, extension=IssuerAlternativeName,
            help='URL to the homepage of your CA.'
        )
        group.add_argument(
            '--crl-url', metavar='URL', action=MultipleURLAction, default=[],
            help='URL to a certificate revokation list. Can be given multiple times.'
        )
        group.add_argument(
            '--ocsp-url', metavar='URL', action=URLAction,
            help='URL of an OCSP responder.'
        )
