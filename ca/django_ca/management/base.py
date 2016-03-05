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

from OpenSSL import crypto

from django.core.management.base import BaseCommand as _BaseCommand
from django.core.management.base import CommandError

from django_ca import ca_settings
from django_ca.models import Certificate
from django_ca.models import CertificateAuthority


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


class CertificateAuthorityAction(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        value = value.strip().upper()
        try:
            value = CertificateAuthority.objects.get(serial=value)
        except CertificateAuthority.DoesNotExist:
            parser.error('%s: Unknown Certiciate Authority.' % value)

        # verify that the private key exists
        if not os.path.exists(value.private_key_path):
            parser.error('%s: %s: Private key does not exist.' % (value, value.private_key_path))

        # try to parse the private key
        try:
            value.key
        except OSError:
            raise CommandError(
                '%s: %s: Could not read private key.' % (value, value.private_key_path))
        except Exception as e:
            # TODO: we should catch unparseable keys in own except clause
            raise CommandError(str(e))

        setattr(namespace, self.dest, value)


class BaseCommand(_BaseCommand):
    certificate_queryset = Certificate.objects.filter(revoked=False)

    def add_algorithm(self, parser):
        """Add the --algorithm option."""

        parser.add_argument(
            '--algorithm', metavar='{sha512,sha256,...}',
            help='Algorithm to use (default: %s).' % ca_settings.CA_DIGEST_ALGORITHM)

    def add_ca(self, parser, arg='--ca', help='Certificate authority to use (default: %s).'):
        default = CertificateAuthority.objects.filter(enabled=True).first()
        help = help % default
        parser.add_argument('%s' % arg, metavar='SERIAL', help=help, default=default,
                            action=CertificateAuthorityAction)

    def add_format(self, parser, default=crypto.FILETYPE_PEM):
        """Add the --format option."""

        help_text = 'The format to use ("DER" is an alias for "ASN1"%s).'
        if default == crypto.FILETYPE_PEM:
            help_text %= ', default: PEM'
        elif default == crypto.FILETYPE_ASN1:
            help_text %= ', default: ASN1'
        elif default == crypto.FILETYPE_TEXT:
            help_text %= ', default: TEXT'
        else:
            help_text %= ''

        parser.add_argument('-f', '--format', metavar='{PEM,ASN1,DER,TEXT}', default=default,
                            action=FormatAction, help=help_text)

    def get_certificate(self, id):
        try:
            return self.certificate_queryset.get_by_serial_or_cn(id)
        except Certificate.DoesNotExist:
            raise CommandError('No valid certificate with CommonName/serial "%s" exists.' % id)
        except Certificate.MultipleObjectsReturned:
            raise CommandError('Multiple valid certificates with CommonName "%s" found.' % id)


class CertCommand(BaseCommand):
    def add_arguments(self, parser):
        parser.add_argument(
            'cert',
            help='''Certificate by CommonName or serial. If you give a CommonName (which is not by
                definition unique) there must be only one valid certificate with the given
                CommonName.''')
        super(CertCommand, self).add_arguments(parser)
