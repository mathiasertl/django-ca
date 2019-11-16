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
from django.utils import timezone

from ... import ca_settings
from ...extensions import SubjectAlternativeName
from ...management.base import BaseSignCommand
from ...models import Certificate
from ...models import Watcher
from ...subject import Subject


class Command(BaseSignCommand):
    help = """Sign a CSR and output signed certificate. The defaults depend on the configured
default profile, currently %s.""" % ca_settings.CA_DEFAULT_PROFILE

    add_extensions_help = '''Values for more complex x509 extensions. This is for advanced usage only, the
profiles already set the correct values for the most common use cases. See
https://django-ca.readthedocs.io/en/latest/extensions.html for more information.'''
    subject_help = '''The certificate subject of the CSR is not used. The default subject is configured
            with the CA_DEFAULT_SUBJECT setting and may be overwritten by a profile named with
            --profile. The --subject option allows you to name a CommonName (which is not usually
            in the defaults) and override any default values.'''

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

    def add_arguments(self, parser):
        self.add_base_args(parser)
        self.add_cn_in_san(parser)

        parser.add_argument(
            '--csr', metavar='FILE',
            help='The path to the certificate to sign, if ommitted, you will be be prompted.')
        self.add_format(parser, opts=['--csr-format'],
                        help_text='Format of the CSR ("ASN1" is an alias for "DER", default: %(default)s)')

        self.add_profile(parser, """Sign certificate based on the given profile. A profile only sets the the
                         default values, options like --key-usage still override the profile.""")

    def handle(self, *args, **options):
        ca = options['ca']
        if ca.expires < timezone.now():
            raise CommandError('Certificate Authority has expired.')
        if ca.revoked:
            raise CommandError('Certificate Authority is revoked.')
        self.test_options(*args, **options)

        # get list of watchers
        watchers = [Watcher.from_addr(addr) for addr in options['watch']]

        # get extensions based on profiles
        kwargs = {
            'cn_in_san': options['cn_in_san'],
            'csr_format': options['csr_format'],

            # TODO: since expires option has a default, it currently overrides profile values
            'expires': options['expires'],
            'extensions': [],
            'password': options['password'],
            'subject': options['subject'] or Subject(),
        }

        for ext in self.sign_extensions:
            if options[ext.key]:
                kwargs['extensions'].append(options[ext.key])

        if 'CN' not in kwargs['subject'] and not options[SubjectAlternativeName.key]:
            raise CommandError("Must give at least a CN in --subject or one or more --alt arguments.")

        # Read the CSR
        if options['csr'] is None:
            self.stdout.write('Please paste the CSR:')
            csr = ''
            while not csr.endswith('-----END CERTIFICATE REQUEST-----\n'):
                csr += '%s\n' % input()
            csr = csr.strip()
        else:
            with open(options['csr'], 'rb') as stream:
                csr = stream.read()

        try:
            cert = Certificate.objects.create_cert(ca, csr, profile=options['profile'], **kwargs)
        except Exception as e:
            raise CommandError(e)

        cert.watchers.add(*watchers)

        if options['out']:
            with open(options['out'], 'w') as f:
                f.write(cert.pub)
        else:
            self.stdout.write(cert.pub)
