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

from datetime import datetime
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.core.management.base import CommandError
from django.utils import six

from django_ca.ca_settings import CA_ALLOW_CA_CERTIFICATES
from django_ca.ca_settings import CA_PROFILES
from django_ca.ca_settings import CA_DEFAULT_EXPIRES
from django_ca.models import Certificate
from django_ca.models import Watcher
from django_ca.utils import get_cert_profile_kwargs
from django_ca.utils import get_cert


class Command(BaseCommand):
    help = "Sign a CSR and output signed certificate."

    def add_arguments(self, parser):
        parser.add_arugment(
            '--cn', help="CommonName to use. If omitted, the first --alt value will be used.")
        parser.add_argument(
            '--days', default=CA_DEFAULT_EXPIRES, type=int,
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
            '--key-usage', metavar='VALUES',
            help='Override the keyUsage extension, e.g. "critical,keyCertSign".')
        parser.add_argument(
            '--ext-key-usage', metavar='VALUES',
            help='Override the extendedKeyUsage extension, e.g. "serverAuth,clientAuth".')

        group = parser.add_argument_group(
            'profiles', """Sign certificate based on the given profile. This overrides the
--key-usage and --ext-key-usage arguments.""")
        group = group.add_mutually_exclusive_group()
        for name, profile in CA_PROFILES.items():
            if CA_ALLOW_CA_CERTIFICATES is False \
                    and profile['basicConstraints']['value'] != 'CA:FALSE':
                continue

            group.add_argument('--%s' % name, action='store_const', const=name, dest='profile',
                               help=profile['desc'])

    def parse_extension(self, value):
        if value.startswith('critical,'):
            return True, value[9:]
        return False, value

    def handle(self, *args, **options):
        if not options['cn'] and not options['alt']:
            raise CommandError("Must give at least --cn or one or more --alt arguments.")
        elif not options['cn']:
            options['cn'] = options['alt'][0]  #TODO: strip any prefix
        elif not options['alt']:
            options['alt'] = [options['cn']]  #TODO: parameter not to do that

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

        # get keyUsage and extendedKeyUsage flags based on profiles
        kwargs = get_cert_profile_kwargs(options['profile'])
        if options['key_usage']:
            kwargs['keyUsage'] = self.parse_extension(options['key_usage'])
        if options['ext_key_usage']:
            kwargs['extendedKeyUsage'] = self.parse_extension(options['ext_key_usage'])

        expires = datetime.today() + timedelta(days=options['days'] + 1)
        expires = expires.replace(hour=0, minute=0, second=0, microsecond=0)

        x509 = get_cert(csr=csr, cn=options['cn'], expires=expires, subjectAltName=options['alt'],
                        **kwargs)
        cert = Certificate(csr=csr, expires=expires)
        cert.x509 = x509
        cert.save()
        cert.watchers.add(*watchers)

        if options['out']:
            with open(options['out'], 'w') as f:
                f.write(cert.pub.decode('utf-8'))
        else:
            print(cert.pub.decode('utf-8'))
