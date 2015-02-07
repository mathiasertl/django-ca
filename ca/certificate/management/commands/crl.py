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

from __future__ import unicode_literals

from datetime import datetime

from django.core.management.base import BaseCommand

from OpenSSL import crypto

from ca.utils import get_ca_crt
from ca.utils import get_ca_key
from certificate.models import Certificate


class Command(BaseCommand):
    help = "Write the certificate revocation list (CRL)."
    args = 'path'

    def handle(self, path, **options):
        crl = crypto.CRL()

        revoked_certs = Certificate.objects.filter(expires__gt=datetime.utcnow(), revoked=True)
        for cert in revoked_certs:
            crl.add_revoked(cert.get_revocation())

        crl = crl.export(get_ca_crt(), get_ca_key())
        with open(path, 'w') as crl_file:
            crl_file.write(crl)
