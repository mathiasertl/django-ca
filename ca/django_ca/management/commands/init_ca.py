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

"""
Inspired by:
https://skippylovesmalorie.wordpress.com/2010/02/12/how-to-generate-a-self-signed-certificate-using-pyopenssl/
"""

import os
import pathlib
from datetime import timedelta

from django.core.management.base import CommandError
from django.utils import timezone

from ... import ca_settings
from ...extensions import IssuerAlternativeName
from ...extensions import NameConstraints
from ...models import CertificateAuthority
from ...tasks import cache_crl
from ...tasks import generate_ocsp_key
from ...tasks import run_task
from ..base import BaseCommand
from ..base import CertificateAuthorityDetailMixin
from ..base import ExpiresAction
from ..base import MultipleURLAction
from ..base import PasswordAction
from ..base import URLAction


class Command(BaseCommand, CertificateAuthorityDetailMixin):
    help = "Create a certificate authority."

    def add_arguments(self, parser):
        self.add_algorithm(parser)

        self.add_key_type(parser)
        self.add_key_size(parser)
        self.add_ecc_curve(parser)

        parser.add_argument(
            '--expires', metavar='DAYS', action=ExpiresAction, default=timedelta(365 * 10),
            help='CA certificate expires in DAYS days (default: %(default)s).'
        )
        self.add_ca(
            parser, '--parent', no_default=True,
            help='''Make the CA an intermediate CA of the named CA. By default, this is a new root CA.''')
        parser.add_argument('name', help='Human-readable name of the CA')
        self.add_subject(
            parser, help='''The subject of the CA in the format "/key1=value1/key2=value2/...",
                            valid keys are %s. If "CN" is not set, the name is used.'''
            % self.valid_subject_keys)
        self.add_password(
            parser, help='Optional password used to encrypt the private key. If no argument is passed, you '
                         'will be prompted.')
        parser.add_argument('--path', type=pathlib.PurePath,
                            help="Path where to store Certificate Authorities (relative to CA_DIR).")
        parser.add_argument('--parent-password', nargs='?', action=PasswordAction, metavar='PASSWORD',
                            prompt='Password for parent CA: ',
                            help='Password for the private key of any parent CA.')

        group = parser.add_argument_group(
            'Default hostname',
            'The default hostname is used to compute default URLs for services like OCSP. The hostname is '
            'usually configured in your settings (current setting: %s), but you can override that value '
            'here. The value must be just the hostname and optionally a port, *without* a protocol, e.g. '
            '"ca.example.com" or "ca.example.com:8000".'
            % ca_settings.CA_DEFAULT_HOSTNAME
        )
        group = group.add_mutually_exclusive_group()
        group.add_argument('--default-hostname', metavar='HOSTNAME',
                           help='Override the the default hostname configured in your settings.')
        group.add_argument('--no-default-hostname', dest='default_hostname', action='store_false',
                           help='Disable any default hostname configured in your settings.')

        group = parser.add_argument_group(
            'pathlen attribute',
            """Maximum number of CAs that can appear below this one. A pathlen of zero (the default) means it
            can only be used to sign end user certificates and not further CAs.""")
        group = group.add_mutually_exclusive_group()
        group.add_argument('--pathlen', default=0, type=int,
                           help='Maximum number of sublevel CAs (default: %(default)s).')
        group.add_argument('--no-pathlen', action='store_const', const=None, dest='pathlen',
                           help='Do not add a pathlen attribute.')

        group = parser.add_argument_group(
            'X509 v3 certificate extensions for CA',
            '''Extensions added to the certificate authority itself. These options cannot be changed without
            creating a new authority.'''
        )
        group.add_argument(
            '--ca-crl-url', metavar='URL', action=MultipleURLAction, default=[],
            help='URL to a certificate revokation list. Can be given multiple times.'
        )
        group.add_argument(
            '--ca-ocsp-url', metavar='URL', action=URLAction,
            help='URL of an OCSP responder.'
        )
        group.add_argument('--ca-issuer-url', metavar='URL', action=URLAction,
                           help='URL to the certificate of your CA (in DER format).')

        nc_group = parser.add_argument_group(
            'Name Constraints',
            "Add name constraints to the CA, limiting what certificates this CA can sign."
        )
        nc_group.add_argument(
            '--permit-name', metavar='NAME', action='append', default=[],
            help='Add the given name to the permitted-subtree.'
        )
        nc_group.add_argument(
            '--exclude-name', metavar='NAME', action='append', default=[],
            help='Add the given name to the excluded-subtree.'
        )

        self.add_ca_args(parser)

    def handle(self, name, subject, **options):
        if not os.path.exists(ca_settings.CA_DIR):  # pragma: no cover
            # TODO: set permissions
            os.makedirs(ca_settings.CA_DIR)

        # In case of CAs, we silently set the expiry date to that of the parent CA if the user specified a
        # number of days that would make the CA expire after the parent CA.
        #
        # The reasoning is simple: When issuing the child CA, the default is automatically after that of the
        # parent if it wasn't issued on the same day.
        parent = options['parent']
        if parent and timezone.now() + options['expires'] > parent.expires:
            options['expires'] = parent.expires
        if parent and not parent.allows_intermediate_ca:
            raise CommandError("Parent CA cannot create intermediate CA due to pathlen restrictions.")
        if not parent and options['ca_crl_url']:
            raise CommandError("CRLs cannot be used to revoke root CAs.")
        if not parent and options['ca_ocsp_url']:
            raise CommandError("OCSP cannot be used to revoke root CAs.")

        # See if we can work with the private key
        if parent:
            self.test_private_key(parent, options['parent_password'])

        # Set CommonName to name if not set in subject
        if 'CN' not in subject:
            subject['CN'] = name

        name_constraints = NameConstraints({
            'value': {
                'permitted': options['permit_name'],
                'excluded': options['exclude_name'],
            }
        })

        issuer_alternative_name = options[IssuerAlternativeName.key]
        if issuer_alternative_name is None:
            issuer_alternative_name = ''

        kwargs = {}
        for opt in ['path', 'parent', 'default_hostname']:
            if options[opt] is not None:
                kwargs[opt] = options[opt]

        try:
            ca = CertificateAuthority.objects.init(
                key_size=options['key_size'], key_type=options['key_type'],
                ecc_curve=options['ecc_curve'],
                algorithm=options['algorithm'],
                expires=options['expires'],
                pathlen=options['pathlen'],
                issuer_url=options['issuer_url'],
                issuer_alt_name=issuer_alternative_name,
                crl_url=options['crl_url'],
                ocsp_url=options['ocsp_url'],
                ca_issuer_url=options['ca_issuer_url'],
                ca_crl_url=options['ca_crl_url'],
                ca_ocsp_url=options['ca_ocsp_url'],
                name_constraints=name_constraints,
                name=name, subject=subject, password=options['password'],
                parent_password=options['parent_password'],
                **kwargs
            )
        except Exception as e:
            raise CommandError(e)

        # Generate OCSP keys and cache CRLs
        run_task(generate_ocsp_key, serial=ca.serial, password=options['password'])
        run_task(cache_crl, serial=ca.serial, password=options['password'])
