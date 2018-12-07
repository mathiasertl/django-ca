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

"""
Inspired by:
https://skippylovesmalorie.wordpress.com/2010/02/12/how-to-generate-a-self-signed-certificate-using-pyopenssl/
"""

import os

from django.core.management.base import CommandError
from django.core.files.storage import default_storage

from ... import ca_settings
from ...models import CertificateAuthority
from ..base import BaseCommand
from ..base import CertificateAuthorityDetailMixin
from ..base import ExpiresAction
from ..base import KeyCurveAction
from ..base import KeySizeAction
from ..base import MultipleURLAction
from ..base import PasswordAction
from ..base import URLAction


class Command(BaseCommand, CertificateAuthorityDetailMixin):
    help = "Create a certificate authority."

    def add_arguments(self, parser):
        self.add_algorithm(parser)

        parser.add_argument(
            '--key-type', choices=['RSA', 'DSA', 'ECC'], default='RSA',
            help="Key type for the CA private key (default: %(default)s).")
        parser.add_argument(
            '--key-size', type=int, action=KeySizeAction, default=4096,
            metavar='{2048,4096,8192,...}',
            help="Size of the key to generate (default: %(default)s).")

        curve_help = 'Elliptic Curve used for generating ECC keys (default: %(default)s).' % {
            'default': ca_settings.CA_DEFAULT_ECC_CURVE.__class__.__name__,
        }
        parser.add_argument('--ecc-curve', type=str, action=KeyCurveAction,
                            default=ca_settings.CA_DEFAULT_ECC_CURVE,
                            help=curve_help)

        parser.add_argument(
            '--expires', metavar='DAYS', action=ExpiresAction, default=365 * 10,
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
        parser.add_argument('--parent-password', nargs='?', action=PasswordAction, metavar='PASSWORD',
                            prompt='Password for parent CA: ',
                            help='Password for the private key of any parent CA.')

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
        group.add_argument(
            '--name-constraint', default=[], action='append', metavar='CONSTRAINT',
            help='''Name constraints for the certificate, can be given multiple times, e.g.
                "permitted,email:.example.com" or "excluded,DNS:.com".''')

        self.add_ca_args(parser)

    def handle(self, name, subject, **options):
        try:
            local_path = default_storage.path(ca_settings.CA_DIR)
            if not os.path.exists(local_path):  # pragma: no cover
                # TODO: set permissions
                os.makedirs(local_path)
        except NotImplementedError:
            # Using external storage. S3 and Minio manage path creation
            pass

        # In case of CAs, we silently set the expiry date to that of the parent CA if the user specified a
        # number of days that would make the CA expire after the parent CA.
        #
        # The reasoning is simple: When issuing the child CA, the default is automatically after that of the
        # parent if it wasn't issued on the same day.
        parent = options['parent']
        if parent and options['expires'] > parent.expires:
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

        try:
            CertificateAuthority.objects.init(
                key_size=options['key_size'], key_type=options['key_type'],
                ecc_curve=options['ecc_curve'],
                algorithm=options['algorithm'],
                expires=options['expires'],
                parent=parent,
                pathlen=options['pathlen'],
                issuer_url=options['issuer_url'],
                issuer_alt_name=options['issuer_alt_name'],
                crl_url=options['crl_url'],
                ocsp_url=options['ocsp_url'],
                ca_issuer_url=options['ca_issuer_url'],
                ca_crl_url=options['ca_crl_url'],
                ca_ocsp_url=options['ca_ocsp_url'],
                name_constraints=options['name_constraint'],
                name=name, subject=subject, password=options['password'],
                parent_password=options['parent_password']
            )
        except Exception as e:
            raise CommandError(e)
