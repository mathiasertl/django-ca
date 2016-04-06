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

from django.core.management.base import CommandError
from django.utils import six

from ... import ca_settings
from ...management.base import BaseCommand
from ...models import Certificate
from ...models import Watcher
from ...utils import get_cert_profile_kwargs
from ...utils import get_cert
from ...utils import parse_date
from ...utils import SUBJECT_FIELDS


class Command(BaseCommand):
    help = """Sign a CSR and output signed certificate. The defaults depend on the configured
default profile, currently %s.""" % ca_settings.CA_DEFAULT_PROFILE

    def add_cn_in_san(self, parser):
        default = ca_settings.CA_PROFILES[ca_settings.CA_DEFAULT_PROFILE]['cn_in_san']

        group = parser.add_argument_group(
            'CommonName in subjectAltName',
            """Whether or not to automatically include the CommonName (given by --cn) in the list
of subjectAltNames (given by --alt).""")
        group = group.add_mutually_exclusive_group()

        group.add_argument(
            '--cn-not-in-san', default=None, action='store_false', dest='cn_in_san',
            help='Do not add the CommonName as subjectAlternativeName%s.' % (
                ' (default)' if not default else ''))
        group.add_argument(
            '--cn-in-san', default=None, action='store_true', dest='cn_in_san',
            help='Add the CommonName as subjectAlternativeName%s.' % (
                ' (default)' if default else ''))

    def add_subject(self, parser):
        subject = ca_settings.CA_PROFILES[ca_settings.CA_DEFAULT_PROFILE]['subject']
        group = parser.add_argument_group(
            'Certificate subject',
            '''The subject to use. Empty values are not included in the subject. The default values
            depend on the default profile and the CA_DEFAULT_SUBJECT setting.''')

        # NOTE: We do not set the default argument here because that would mask the user not
        # setting anything at all.
        group.add_argument(
            '--C', metavar='CC',
            help='Two-letter country code, e.g. "AT" (default: "%s").' % (subject.get('C') or '')
        )
        group.add_argument(
            '--ST', metavar='STATE',
            help='The state you are in (default "%s").' % (subject.get('ST') or '')
        )
        group.add_argument(
            '--L', metavar='CITY',
            help='The city you are in (default "%s").' % (subject.get('L') or '')
        )
        group.add_argument(
            '--O', metavar='ORG',
            help='Your organization (default: "%s").' % (subject.get('O') or '')
        )
        group.add_argument(
            '--OU', metavar='ORGUNIT',
            help='Your organizational unit (default: "%s").' % (subject.get('OU') or '')
        )
        group.add_argument(
            '--CN', help="CommonName to use. If omitted, the first --alt value will be used."
        )
        group.add_argument(
            '--E', metavar='E-Mail', dest='emailAddress',
            help='E-mail to use (default: "%s").' % (subject.get('emailAddress') or '')
        )

    def add_arguments(self, parser):
        self.add_subject(parser)
        self.add_cn_in_san(parser)
        self.add_algorithm(parser)
        self.add_ca(parser)

        parser.add_argument(
            '--days', default=ca_settings.CA_DEFAULT_EXPIRES, type=int,
            help='Sign the certificate for DAYS days (default: %(default)s)')
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
            'profiles', """Sign certificate based on the given profile. A profile only sets the
the default values, options like --key-usage still override the profile.""")
        group = group.add_mutually_exclusive_group()
        for name, profile in ca_settings.CA_PROFILES.items():
            group.add_argument('--%s' % name, action='store_const', const=name, dest='profile',
                               help=profile['desc'])

    def parse_extension(self, value):
        if value.startswith('critical,'):
            return True, value[9:].encode('utf-8')
        return False, value.encode('utf-8')

    def handle(self, *args, **options):
        if not options['CN'] and not options['alt']:
            raise CommandError("Must give at least --CN or one or more --alt arguments.")

        if options['csr'] is None:
            self.stdout.write('Please paste the CSR:')
            csr = ''
            while not csr.endswith('-----END CERTIFICATE REQUEST-----\n'):
                csr += '%s\n' % six.moves.input()
            csr = csr.strip()
        else:
            csr = open(options['csr']).read()

        # get list of watchers
        ca = options['ca']
        watchers = [Watcher.from_addr(addr) for addr in options['watch']]

        # get keyUsage and extendedKeyUsage flags based on profiles
        kwargs = get_cert_profile_kwargs(options['profile'])
        if options['cn_in_san'] is not None:
            kwargs['cn_in_san'] = options['cn_in_san']
        if options['key_usage']:
            kwargs['keyUsage'] = self.parse_extension(options['key_usage'])
        if options['ext_key_usage']:
            kwargs['extendedKeyUsage'] = self.parse_extension(options['ext_key_usage'])

        # update subject with arguments from the command line
        kwargs.setdefault('subject', {})
        for field in SUBJECT_FIELDS:
            value = options.get(field)
            if value == '' and field in kwargs['subject']:
                del kwargs['subject'][field]
            elif value:
                kwargs['subject'][field] = options[field]

        x509 = get_cert(ca=ca, csr=csr, algorithm=options['algorithm'], expires=options['days'],
                        subjectAltName=options['alt'], **kwargs)
        expires = parse_date(x509.get_notAfter().decode('utf-8'))
        cert = Certificate(ca=ca, csr=csr, expires=expires)
        cert.x509 = x509
        cert.save()
        cert.watchers.add(*watchers)

        if options['out']:
            with open(options['out'], 'w') as f:
                f.write(cert.pub)
        else:
            self.stdout.write(cert.pub)
