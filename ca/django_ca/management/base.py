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

from OpenSSL import crypto

from django.core.management.base import BaseCommand as _BaseCommand
from django.core.management.base import CommandError
from django.core.management.base import OutputWrapper
from django.core.management.color import no_style
from django.core.validators import URLValidator
from django.utils import six

from django_ca import ca_settings
from django_ca.utils import is_power2
from django_ca.utils import parse_subject
from django_ca.utils import SUBJECT_FIELDS
from django_ca.models import Certificate
from django_ca.models import CertificateAuthority


class SubjectAction(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        try:
            value = parse_subject(value)
        except ValueError as e:
            parser.error(e)
        setattr(namespace, self.dest, value)


class FormatAction(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        value = value.strip().upper()
        if value == 'DER':
            value = 'ASN1'
        try:
            value = getattr(crypto, 'FILETYPE_%s' % value)
        except AttributeError:
            parser.error('Unknown format "%s".' % value)
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


class CertificateAuthorityAction(argparse.Action):
    def __init__(self, allow_disabled=False, **kwargs):
        super(CertificateAuthorityAction, self).__init__(**kwargs)
        self.allow_disabled = allow_disabled

    def __call__(self, parser, namespace, value, option_string=None):
        value = value.strip().upper()

        qs = CertificateAuthority.objects.all()
        if self.allow_disabled is False:
            qs = qs.enabled()

        try:
            value = qs.get(serial=value)
        except CertificateAuthority.DoesNotExist:
            parser.error('%s: Unknown Certiciate Authority.' % value)

        # verify that the private key exists
        if not os.path.exists(value.private_key_path):
            parser.error('%s: %s: Private key does not exist.' % (value, value.private_key_path))

        # try to parse the private key
        try:
            value.key
        except (OSError, crypto.Error):
            raise parser.error(
                '%s: %s: Could not read private key.' % (value, value.private_key_path))

        setattr(namespace, self.dest, value)


class URLAction(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        validator = URLValidator()
        try:
            validator(value)
        except:
            parser.error('%s: Not a valid URL.' % value)
        setattr(namespace, self.dest, value)


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

        if ending and not msg.endswith(ending):  # pragma: no cover
            msg += ending
        self._out.write(msg)


class BaseCommand(_BaseCommand):
    certificate_queryset = Certificate.objects.filter(revoked=False)
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

        parser.add_argument(
            '--algorithm', metavar='{sha512,sha256,...}', default=ca_settings.CA_DIGEST_ALGORITHM,
            help='Algorithm to use (default: %(default)s).')

        
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

    def add_format(self, parser, default=crypto.FILETYPE_PEM):
        """Add the --format option."""

        help_text = 'The format to use ("DER" is an alias for "ASN1"%s).'
        if default == crypto.FILETYPE_PEM:
            help_text %= ', default: PEM'
        elif default == crypto.FILETYPE_ASN1:  # pragma: no cover
            help_text %= ', default: ASN1'
        elif default == crypto.FILETYPE_TEXT:  # pragma: no cover
            help_text %= ', default: TEXT'
        else:  # pragma: no cover
            help_text %= ''

        parser.add_argument('-f', '--format', metavar='{PEM,ASN1,DER,TEXT}', default=default,
                            action=FormatAction, help=help_text)

    def get_certificate(self, id):
        try:
            return self.certificate_queryset.get_by_serial_or_cn(id)
        except Certificate.DoesNotExist:
            raise CommandError('No valid certificate with CommonName/serial "%s" exists.' % id)
        except Certificate.MultipleObjectsReturned:  # pragma: no cover - super unlikely
            raise CommandError('Multiple valid certificates with CommonName "%s" found.' % id)


class CertCommand(BaseCommand):
    def add_arguments(self, parser):
        parser.add_argument(
            'cert',
            help='''Certificate by CommonName or serial. If you give a CommonName (which is not by
                definition unique) there must be only one valid certificate with the given
                CommonName.''')
        super(CertCommand, self).add_arguments(parser)


class CertificateAuthorityDetailMixin(object):
    def add_ca_args(self, parser):
        group = parser.add_argument_group(
            'x509 extensions', 'Define various x509 extensions used when signing certificates.')
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
