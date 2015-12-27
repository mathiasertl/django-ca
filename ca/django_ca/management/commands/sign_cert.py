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

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import six

from django_ca.models import Certificate
from django_ca.models import Watcher


class Command(BaseCommand):
    help = "Sign a CSR and output signed certificate."

    def add_arguments(self, parser):
        parser.add_argument(
            '--days', default=720, type=int,
            help='Sign the certificate for DAYS days (default: %(default)s)')
        parser.add_argument(
            '--algorithm',
            help='Algorithm to use (default: The DIGEST_ALGORITHM setting in settings.py)')
        parser.add_argument(
            '--csr', metavar='FILE',
            help='The path to the certificate to sign, if ommitted, you will be be prompted.')
        parser.add_argument(
            '--alt', metavar='DOMAIN', action='append', default=[],
            help='Add a subjectAltName to the certificate (may be given multiple times)')
        parser.add_argument(
            '--watch', metavar='EMAIL', action='append', default=[],
            help='Email EMAIL when this certificate expires (may be given multiple times)')
        parser.add_argument(
            '--out', metavar='FILE',
            help='Save signed certificate to FILE. If omitted, print to stdout.')
        parser.add_argument(
            '--key-usage', default=','.join(settings.CA_KEY_USAGE), metavar='NAMES',
            help="Override keyUsage attribute (default: CA_KEY_USAGE setting: %(default)s).")
        parser.add_argument(
            '--ext-key-usage', default=','.join(settings.CA_EXT_KEY_USAGE), metavar='NAMES',
            help="Override keyUsage attribute (default: CA_EXT_KEY_USAGE setting: %(default)s).")
        parser.add_argument(
            '--ocsp', default=False, action='store_true',
            help="Issue a certificate for an OCSP server.")

    def handle(self, *args, **options):
        if options['csr'] is None:
            print('Please paste the CSR:')
            csr = ''
            while not csr.endswith('-----END CERTIFICATE REQUEST-----\n'):
                csr += '%s\n' % six.moves.input()
            csr = csr.strip()
        else:
            csr = open(options['csr']).read()

        # get list of watchers
        watchers = [Watcher.from_addr(addr) for addr in options['watch']]

        if options['ocsp'] is True:
            key_usage = (str('nonRepudiation'), str('digitalSignature'), str('keyEncipherment'), )
            ext_key_usage = (str('OCSPSigning'), )
        else:
            key_usage = options['key_usage'].split(',')
            ext_key_usage = options['ext_key_usage'].split(',')

        cert = Certificate.objects.from_csr(
            csr, subjectAltNames=options['alt'], days=options['days'],
            algorithm=options['algorithm'], watchers=watchers, key_usage=key_usage,
            ext_key_usage=ext_key_usage)

        if options['out']:
            with open(options['out'], 'w') as f:
                f.write(cert.pub.decode('utf-8'))
        else:
            print(cert.pub.decode('utf-8'))
