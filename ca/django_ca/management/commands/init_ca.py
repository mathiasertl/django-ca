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

from datetime import datetime
from datetime import timedelta
from getpass import getpass

from django.core.management.base import CommandError

from OpenSSL import crypto

from django_ca import ca_settings
from django_ca.models import CertificateAuthority
from django_ca.utils import get_basic_cert
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

    def handle(self, name, country, state, city, org, ou, cn, **options):
        # get a possible parent CA
        parent = options['parent']

        if parent is not None:
            try:
                parent.key
            except FileNotFoundError:
                raise CommandError(
                    '%s: Parent CA private key not available.' % parent.private_key_path)
            except Exception as e:
                # TODO: we should catch unparseable keys in own except clause
                raise CommandError(str(e))

        # check that the bitsize is a power of two
        is_power2 = lambda num: num != 0 and ((num & (num - 1)) == 0)
        if not is_power2(options['key_size']):
            raise CommandError("%s: Key size must be a power of two." % options['key_size'])
        elif options['key_size'] < 2048:
            raise CommandError("%s: Key must have a size of at least 2048 bits." % options['key_size'])

        if not os.path.exists(ca_settings.CA_DIR):
            os.makedirs(ca_settings.CA_DIR)

        if not options.get('algorithm'):
            options['algorithm'] = ca_settings.CA_DIGEST_ALGORITHM

        now = datetime.utcnow()
        expires = now + timedelta(days=options['expires'])

        key = crypto.PKey()
        key.generate_key(getattr(crypto, 'TYPE_%s' % options['key_type']), options['key_size'])

        # set basic properties
        cert = get_basic_cert(expires)
        cert.get_subject().C = country
        cert.get_subject().ST = state
        cert.get_subject().L = city
        cert.get_subject().O = org
        cert.get_subject().OU = ou
        cert.get_subject().CN = cn
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)

        # sign the certificate
        if parent is None:
            cert.sign(key, options['algorithm'])
        else:
            cert.sign(sign_key, options['algorithm'])

        san = bytes('DNS:%s' % cn, 'utf-8')
        cert.add_extensions([
            crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE, pathlen:0'),
            crypto.X509Extension(b'keyUsage', 0, b'keyCertSign,cRLSign'),
            crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=cert),
            crypto.X509Extension(b'subjectAltName', 0, san)
        ])
        cert.add_extensions([
            crypto.X509Extension(b'authorityKeyIdentifier', False, b'keyid:always', issuer=cert),
        ])

        if options['password'] is None:
            args = []
        elif options['password'] == '':
            args = ['des3', getpass()]
        else:
            args = ['des3', options['password']]


        # create certificate in database
        ca = CertificateAuthority(name=name, parent=parent)
        ca.x509 = cert
        ca.private_key_path = os.path.join(ca_settings.CA_DIR, '%s.key' % ca.serial)
        ca.save()

        oldmask = os.umask(247)
        with open(ca.private_key_path, 'w') as key_file:
            key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key, *args)
            key_file.write(key.decode('utf-8'))
        os.umask(oldmask)
