# -*- coding: utf-8 -*-
#
# This file is part of fsinf-certificate-authority (https://github.com/fsinf/certificate-authority).
#
# fsinf-certificate-authority is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software Foundation, either
# version 3 of the License, or (at your option) any later version.
#
# fsinf-certificate-authority is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
# PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# fsinf-certificate-authority.  If not, see <http://www.gnu.org/licenses/>.

"""
Inspired by:
https://skippylovesmalorie.wordpress.com/2010/02/12/how-to-generate-a-self-signed-certificate-using-pyopenssl/
"""

from __future__ import unicode_literals

import os
import uuid

from datetime import datetime
from datetime import timedelta
from getpass import getpass
from optparse import make_option

from django.conf import settings
from django.core.management.base import BaseCommand
from django.core.management.base import CommandError

from OpenSSL import crypto

from ca.utils import format_date


class Command(BaseCommand):
    help = "Initiate a certificate authority."
    args = "Country State City Org OrgUnit CommonName"

    option_list = BaseCommand.option_list + (
        make_option('--expires', metavar='DAYS', type="int", default=365 * 10,
                    help='CA certificate expires in DAYS days (default: %default).'
        ),
        make_option('--password', nargs=1,
                    help="Optional password used to encrypt the private key. If omitted, no "
                    "password is used, use \"--password=\" to prompt for a password.")
    )

    def handle(self, country, state, city, org, ou, cn, **options):
        if os.path.exists(settings.CA_KEY):
            raise CommandError("%s: private key already exists." % settings.CA_KEY)
        if os.path.exists(settings.CA_CRT):
            raise CommandError("%s: public key already exists." % settings.CA_CRT)

        now = datetime.utcnow()
        expires = now + timedelta(days=options['expires'])

        key = crypto.PKey()
        key.generate_key(settings.CA_KEY_TYPE, settings.CA_BITSIZE)

        cert = crypto.X509()
        cert.get_subject().C = country
        cert.get_subject().ST = state
        cert.get_subject().L = city
        cert.get_subject().O = org
        cert.get_subject().OU = ou
        cert.get_subject().CN = cn
        cert.set_serial_number(uuid.uuid4().int)
        cert.set_notBefore(format_date(now))
        cert.set_notAfter(format_date(expires))
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, settings.DIGEST_ALGORITHM)

        # add various extensions
        cert.add_extensions([
            crypto.X509Extension(str('basicConstraints'), True, str('CA:TRUE, pathlen:0')),
            crypto.X509Extension(str('keyUsage'), 0, str('keyCertSign,cRLSign')),
            crypto.X509Extension(str('subjectKeyIdentifier'), False, str('hash'), subject=cert),
        ])
        cert.add_extensions([
            crypto.X509Extension(str('authorityKeyIdentifier'), False, str('keyid:always'), issuer=cert),
        ])

        if options['password'] is None:
            args = []
        elif options['password'] == '':
            args = [str('des3'), getpass()]
        else:
            args = [str('des3'), options['password']]

        with open(settings.CA_KEY, 'w') as key_file:
            # TODO: optionally add 'des3', 'passphrase' as args
            key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key, *args))
        with open(settings.CA_CRT, 'w') as cert_file:
            cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
