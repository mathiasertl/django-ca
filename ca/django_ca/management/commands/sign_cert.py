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

from collections import OrderedDict

from django.core.management.base import CommandError
from django.utils import six
from django.utils import timezone

from ... import ca_settings
from ...management.base import BaseCommand
from ...models import Certificate
from ...models import Watcher
from ...utils import get_cert_profile_kwargs
from ..base import ExpiresAction


class Command(BaseCommand):
    help = """Sign a CSR and output signed certificate. The defaults depend on the configured
default profile, currently %s.""" % ca_settings.CA_DEFAULT_PROFILE

    def add_cn_in_san(self, parser):
        default = ca_settings.CA_PROFILES[ca_settings.CA_DEFAULT_PROFILE]['cn_in_san']

        group = parser.add_argument_group(
            'CommonName in subjectAltName',
            """Whether or not to automatically include the CommonName (given in --subject) in the
            list of subjectAltNames (given by --alt).""")
        group = group.add_mutually_exclusive_group()

        group.add_argument(
            '--cn-not-in-san', default=None, action='store_false', dest='cn_in_san',
            help='Do not add the CommonName as subjectAlternativeName%s.' % (
                ' (default)' if not default else ''))
        group.add_argument(
            '--cn-in-san', default=None, action='store_true', dest='cn_in_san',
            help='Add the CommonName as subjectAlternativeName%s.' % (
                ' (default)' if default else ''))

    def add_subject_group(self, parser):
        # TODO: show the default
        #subject = ca_settings.CA_PROFILES[ca_settings.CA_DEFAULT_PROFILE]['subject']
        group = parser.add_argument_group(
            'Certificate subject',
            '''The certificate subject of the CSR is not used. The default subject is configured
            with the CA_DEFAULT_SUBJECT setting and may be overwritten by a profile named with
            --profile. The --subject option allows you to name a CommonName (which is not usually
            in the defaults) and override any default values.'''
        )

        # NOTE: We do not set the default argument here because that would mask the user not
        # setting anything at all.
        self.add_subject(
            group, arg='--subject', metavar='/key1=value1/key2=value2/...',
            help='''Valid keys are %s. Pass an empty value (e.g. "/C=/ST=...") to remove a field
                 from the subject.''' % self.valid_subject_keys)

    def add_arguments(self, parser):
        self.add_subject_group(parser)
        self.add_cn_in_san(parser)
        self.add_algorithm(parser)
        self.add_ca(parser)

        parser.add_argument(
            '--expires', default=ca_settings.CA_DEFAULT_EXPIRES, action=ExpiresAction,
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

        group = parser.add_argument_group('X509 v3 certificate extensions')
        group.add_argument(
            '--key-usage', metavar='VALUES',
            help='Override the keyUsage extension, e.g. "critical,keyCertSign".')
        group.add_argument(
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
            return True, value[9:]
        return False, value

    def handle(self, *args, **options):
        ca = options['ca']
        if ca.expires < options['expires']:
            max_days = (ca.expires - timezone.now()).days
            raise CommandError(
                'Certificate would outlive CA, maximum expiry for this CA is %s days.' % max_days)

        # get list of watchers
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
        kwargs.setdefault('subject', OrderedDict())
        if options.get('subject'):
            kwargs['subject'].update(options['subject'])  # update from command line

        # filter empty values
        kwargs['subject'] = OrderedDict([(k, v) for k, v in kwargs['subject'].items() if v])

        if not kwargs['subject'].get('CN') and not options['alt']:
            raise CommandError(
                "Must give at least a CN in --subject or one or more --alt arguments.")

        # Read the CSR
        if options['csr'] is None:
            self.stdout.write('Please paste the CSR:')
            csr = ''
            while not csr.endswith('-----END CERTIFICATE REQUEST-----\n'):
                csr += '%s\n' % six.moves.input()
            csr = csr.strip()
        else:
            csr = open(options['csr']).read()

        cert = Certificate(ca=ca, csr=csr)
        cert.x509 = Certificate.objects.init(
            ca=ca, csr=csr, algorithm=options['algorithm'], expires=options['expires'],
            subjectAltName=options['alt'], **kwargs)
        cert.save()
        cert.watchers.add(*watchers)

        if options['out']:
            with open(options['out'], 'w') as f:
                f.write(cert.pub)
        else:
            self.stdout.write(cert.pub)
