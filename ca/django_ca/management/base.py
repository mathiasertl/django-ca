# -*- coding: utf-8 -*-
#
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
import os
import sys
from datetime import datetime
from datetime import timedelta

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

from django.core.management.base import BaseCommand as _BaseCommand
from django.core.management.base import OutputWrapper
from django.core.management.color import no_style
from django.core.validators import URLValidator
from django.utils import six

from django_ca import ca_settings
from django_ca.models import Certificate
from django_ca.models import CertificateAuthority
from django_ca.utils import SUBJECT_FIELDS
from django_ca.utils import is_power2
from django_ca.utils import parse_name


class SubjectAction(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        try:
            value = parse_name(value)
        except ValueError as e:
            parser.error(e)
        setattr(namespace, self.dest, value)


class FormatAction(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        value = value.strip().upper()
        if value == 'ASN1':
            value = 'DER'

        try:
            value = getattr(Encoding, value)
        except AttributeError:
            parser.error('Unknown format "%s".' % value)

        setattr(namespace, self.dest, value)


class AlgorithmAction(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        value = value.strip().upper()

        try:
            value = getattr(hashes, value)()
        except AttributeError:
            parser.error('Unknown hash algorithm: %s' % value)

        setattr(namespace, self.dest, value)


class KeySizeAction(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        option_string = option_string or 'key size'

        if not is_power2(value):
            parser.error('%s must be a power of two (2048, 4096, ...)' % option_string)
        elif value < ca_settings.CA_MIN_KEY_SIZE:
            parser.error('%s must be at least %s bits.'
                         % (option_string, ca_settings.CA_MIN_KEY_SIZE))
        setattr(namespace, self.dest, value)


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
    def __init__(self, allow_disabled=False, **kwargs):
        super(CertificateAuthorityAction, self).__init__(**kwargs)
        self.allow_disabled = allow_disabled

    def __call__(self, parser, namespace, value, option_string=None):
        qs = CertificateAuthority.objects.all()
        if self.allow_disabled is False:
            qs = qs.enabled()

        try:
            value = qs.get_by_serial_or_cn(value)
        except CertificateAuthority.DoesNotExist:
            parser.error('%s: Certiciate authority not found.' % value)
        except CertificateAuthority.MultipleObjectsReturned:
            parser.error('%s: Multiple Certificate authorities match.' % value)

        # verify that the private key exists
        if not os.path.exists(value.private_key_path):
            parser.error('%s: %s: Private key does not exist.' % (value, value.private_key_path))

        # try to parse the private key
        try:
            value.key
        except Exception as e:
            raise parser.error('%s: %s: Could not read private key: %s' % (value, value.private_key_path, e))

        setattr(namespace, self.dest, value)


class URLAction(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        validator = URLValidator()
        try:
            validator(value)
        except:
            parser.error('%s: Not a valid URL.' % value)
        setattr(namespace, self.dest, value)


class ExpiresAction(argparse.Action):
    def __init__(self, *args, **kwargs):
        kwargs['type'] = int  # force int
        self.now = kwargs.pop('now', None)  # for testing

        default = kwargs.get('default')  # default may either be int or datetime
        if isinstance(default, int):
            kwargs['default'] = self._get_delta(kwargs['default'])

        super(ExpiresAction, self).__init__(*args, **kwargs)

    def _get_delta(self, value):
        now = self.now
        if now is None:
            now = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

        return now + timedelta(days=value + 1)

    def __call__(self, parser, namespace, value, option_string=None):
        if value < 0:
            raise parser.error("Expires must not be negative.")

        setattr(namespace, self.dest, self._get_delta(value))


class MultipleURLAction(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        validator = URLValidator()
        try:
            validator(value)
        except:
            parser.error('%s: Not a valid URL.' % value)

        if getattr(namespace, self.dest) is None:
            setattr(namespace, self.dest, [])

        getattr(namespace, self.dest).append(value)


class BinaryOutputWrapper(OutputWrapper):
    def __init__(self, out, style_func=None, ending=b'\n'):
        super(BinaryOutputWrapper, self).__init__(out, style_func=None, ending=ending)

    def write(self, msg, style_func=None, ending=None):
        ending = self.ending if ending is None else ending
        if six.PY3 is True and isinstance(msg, str):  # pragma: no cover
            msg = msg.encode('utf-8')
        elif six.PY2 is True and isinstance(msg, six.text_type):  # pragma: no cover
            msg = msg.encode('utf-8')

        if ending and not msg.endswith(ending):  # pragma: no cover
            msg += ending
        self._out.write(msg)


class BaseCommand(_BaseCommand):
    binary_output = False

    # TODO/Django1.9: Only necessary in Django 1.8
    requires_system_checks = True

    def __init__(self, stdout=None, stderr=None, no_color=False):
        if self.binary_output is True and six.PY3 is True:
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

        default = ca_settings.CA_DIGEST_ALGORITHM

        try:
            default = getattr(hashes, default.upper())()
        except AttributeError:
            parser.error('Unknown hash algorithm: %s' % default)

        help = 'The HashAlgorithm that will be used to generate the signature (default: %(default)s).' % {
            'default': default.name, }

        parser.add_argument(
            '--algorithm', metavar='{sha512,sha256,...}', default=default, action=AlgorithmAction, help=help)

    @property
    def valid_subject_keys(self):
        fields = ['"%s"' % f for f in SUBJECT_FIELDS]
        return '%s and %s' % (', '.join(fields[:-1]), fields[-1])

    def add_subject(self, parser, arg='subject', metavar=None, help=None):
        parser.add_argument(arg, action=SubjectAction, metavar=metavar, help=help)

    def add_ca(self, parser, arg='--ca',
               help='Certificate authority to use (default: %(default)s).',
               allow_disabled=False, no_default=False):
        if no_default is True:
            default = None
        else:
            default = CertificateAuthority.objects.enabled().first()

        help = help % {'default': default.serial if default else None}
        parser.add_argument('%s' % arg, metavar='SERIAL', help=help, default=default,
                            allow_disabled=allow_disabled, action=CertificateAuthorityAction)

    def add_format(self, parser, default=Encoding.PEM):
        """Add the --format option."""

        help_text = 'The format to use ("ASN1" is an alias for "DER", default: %s).' % default.name
        parser.add_argument('-f', '--format', metavar='{PEM,ASN1,DER}', default=default,
                            action=FormatAction, help=help_text)


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
            '--issuer-alt-name', metavar='URL', action=URLAction,
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
