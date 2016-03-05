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

from collections import OrderedDict
from getpass import getpass

from django.core.management.base import CommandError

from OpenSSL import crypto

from django_ca import ca_settings
from django_ca.models import CertificateAuthority
from django_ca.management.base import BaseCommand


class Command(BaseCommand):
    help = "Initiate a certificate authority."

    def add_arguments(self, parser):
        self.add_algorithm(parser)

        type_choices = [t[5:] for t in dir(crypto) if t.startswith('TYPE_')]
        type_default = 'RSA' if 'RSA' in type_choices else type_choices[0]
        parser.add_argument(
            '--key-type', choices=type_choices, default=type_default,
            help="Key type for the CA private key (default: %(default)s).")
        parser.add_argument(
            '--key-size', type=int, default=4096, metavar='{2048,4096,8192,...}',
            help="Size of the key to generate (default: %(default)s).")

        parser.add_argument(
            '--expires', metavar='DAYS', type=int, default=365 * 10,
            help='CA certificate expires in DAYS days (default: %(default)s).'
        )
        self.add_ca(parser, '--parent', help='Serial of the parent CA (default: %s).')
        parser.add_argument(
            '--password', nargs=1,
            help="Optional password used to encrypt the private key. If omitted, no "
                 "password is used, use \"--password=\" to prompt for a password.")
        parser.add_argument('name', help='Human-readable name of the CA')
        parser.add_argument('country', help='Two-letter country code, e.g. "US" or "AT".')
        parser.add_argument('state', help='State for this CA.')
        parser.add_argument('city', help='City for this CA.')
        parser.add_argument('org', help='Organization where this CA is used.')
        parser.add_argument('ou', help='Organizational Unit where this CA is used.')
        parser.add_argument('cn', help='Common name for this CA.')

        group = parser.add_argument_group(
            'pathlen attribute',
            """Maximum number of CAs that can appear below this one. A pathlen of zero (the
            default) means it can only be used to sign end user certificates and not further
            CAs.""")
        group = group.add_mutually_exclusive_group()
        group.add_argument('--pathlen', default=0, type=int,
                           help='Maximum number of sublevel CAs (default: %(default)s).')
        group.add_argument('--no-pathlen', action='store_false', dest='pathlen',
                           help='Do not add a pathlen attribute.')

    def handle(self, name, country, state, city, org, ou, cn, **options):
        if not os.path.exists(ca_settings.CA_DIR):
            os.makedirs(ca_settings.CA_DIR)

        if not options.get('algorithm'):
            options['algorithm'] = ca_settings.CA_DIGEST_ALGORITHM

        if options['password'] is None:
            args = []
        elif options['password'] == '':
            args = ['des3', getpass()]
        else:
            args = ['des3', options['password']]

        subject = OrderedDict([
            ('C', country), ('ST', state), ('L', city), ('O', org), ('OU', ou), ('CN', cn), ])

        try:
            key, ca = CertificateAuthority.objects.init(
                key_size=options['key_size'], key_type=options['key_type'],
                algorithm=options['algorithm'],
                expires=options['expires'],
                parent=options['parent'],
                pathlen=options['pathlen'],
                name=name, subject=subject)
        except Exception as e:
            raise CommandError(e)

        oldmask = os.umask(247)
        with open(ca.private_key_path, 'w') as key_file:
            key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key, *args)
            key_file.write(key.decode('utf-8'))
        os.umask(oldmask)
