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
from optparse import make_option

from django.conf import settings
from django.core.management.base import BaseCommand
from django.core.management.base import CommandError

from OpenSSL import crypto


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
        key_path = os.path.join(settings.CA_DIR, 'ca.key')
        crt_path = os.path.join(settings.CA_DIR, 'ca.crt')
        if os.path.exists(key_path):
            raise CommandError("%s: private key already exists." % key_path)
        if os.path.exists(crt_path):
            raise CommandError("%s: public key already exists." % crt_path)

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
        cert.gmtime_adj_notBefore(now.strftime('%Y%m%d%H%M%SZ'))
        cert.gmtime_adj_notAfter(expires.strftime('%Y%m%d%H%M%SZ'))
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, settings.DIGEST_ALGORITHM)

        with open(key_path, 'w') as key_file:
            # TODO: optionally add 'des3', 'passphrase' as args
            key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        with open(crt_path, 'w') as cert_file:
            cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
