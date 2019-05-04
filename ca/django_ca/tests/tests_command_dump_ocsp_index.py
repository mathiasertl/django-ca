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
# see <http://www.gnu.org/licenses/>

import os
import shutil
import tempfile
from datetime import datetime
from datetime import timedelta

from freezegun import freeze_time

from .base import DjangoCAWithCertTestCase
from .base import certs
from .base import timestamps

basic = """V\t{child-cert[ocsp-expires]}\t\t{child-cert[ocsp-serial]}\tunknown\t{child-cert[subject]}
V\t{profile-client[ocsp-expires]}\t\t{profile-client[ocsp-serial]}\tunknown\t{profile-client[subject]}
V\t{profile-server[ocsp-expires]}\t\t{profile-server[ocsp-serial]}\tunknown\t{profile-server[subject]}
V\t{profile-webserver[ocsp-expires]}\t\t{profile-webserver[ocsp-serial]}\tunknown\t{profile-webserver[subject]}
V\t{profile-enduser[ocsp-expires]}\t\t{profile-enduser[ocsp-serial]}\tunknown\t{profile-enduser[subject]}
V\t{profile-ocsp[ocsp-expires]}\t\t{profile-ocsp[ocsp-serial]}\tunknown\t{profile-ocsp[subject]}
V\t{no-extensions[ocsp-expires]}\t\t{no-extensions[ocsp-serial]}\tunknown\t{no-extensions[subject]}
V\t{all-extensions[ocsp-expires]}\t\t{all-extensions[ocsp-serial]}\tunknown\t{all-extensions[subject]}
""".format(**certs)  # NOQA

all_expired = """E\t{child-cert[ocsp-expires]}\t\t{child-cert[ocsp-serial]}\tunknown\t{child-cert[subject]}
E\t{profile-client[ocsp-expires]}\t\t{profile-client[ocsp-serial]}\tunknown\t{profile-client[subject]}
E\t{profile-server[ocsp-expires]}\t\t{profile-server[ocsp-serial]}\tunknown\t{profile-server[subject]}
E\t{profile-webserver[ocsp-expires]}\t\t{profile-webserver[ocsp-serial]}\tunknown\t{profile-webserver[subject]}
E\t{profile-enduser[ocsp-expires]}\t\t{profile-enduser[ocsp-serial]}\tunknown\t{profile-enduser[subject]}
E\t{profile-ocsp[ocsp-expires]}\t\t{profile-ocsp[ocsp-serial]}\tunknown\t{profile-ocsp[subject]}
E\t{no-extensions[ocsp-expires]}\t\t{no-extensions[ocsp-serial]}\tunknown\t{no-extensions[subject]}
E\t{all-extensions[ocsp-expires]}\t\t{all-extensions[ocsp-serial]}\tunknown\t{all-extensions[subject]}
"""

ecc_ca = "V\t{ecc-cert[ocsp-expires]}\t\t{ecc-cert[ocsp-serial]}\tunknown\t{ecc-cert[subject]}\n"

revoked_first = "R\t{ecc-cert[ocsp-expires]}\t{revoked}\t{ecc-cert[ocsp-serial]}\tunknown\t{ecc-cert[subject]}\n"  # NOQA
revoked_second = "R\t{ecc-cert[ocsp-expires]}\t{revoked},unspecified\t{ecc-cert[ocsp-serial]}\tunknown\t{ecc-cert[subject]}\n"  # NOQA


class OCSPIndexTestCase(DjangoCAWithCertTestCase):
    timeformat = '%y%m%d%H%M%SZ'

    def assertIndex(self, ca=None, expected='', **context):
        if ca is None:
            ca = self.cas['child']

        context.update(certs)
        stdout, stderr = self.cmd('dump_ocsp_index', ca=ca)
        self.assertEqual(stdout, expected.format(**context))
        self.assertEqual(stderr, '')

    @freeze_time(timestamps['everything_valid'])
    def test_basic(self):
        self.assertIndex(expected=basic)

    @freeze_time(timestamps['everything_expired'])
    def test_all_expired(self):
        # All certificates are expired by now
        self.assertIndex(expected=all_expired)

    @freeze_time(timestamps['before_everything'])
    def test_before_everything(self):
        # Certs are not yet valid
        self.assertIndex(expected=basic)

    @freeze_time(timestamps['everything_valid'])
    def test_ecc_ca(self):
        # test another CA
        self.assertIndex(ca=self.cas['ecc'], expected=ecc_ca)

    @freeze_time(timestamps['everything_valid'])
    def test_file(self):
        tmpdir = tempfile.mkdtemp()

        try:
            path = os.path.join(tmpdir, 'ocsp-index.txt')

            stdout, stderr = self.cmd('dump_ocsp_index', path, ca=self.cas['child'])
            self.assertEqual(stdout, '')
            self.assertEqual(stderr, '')

            with open(path) as stream:
                data = stream.read()
            self.assertEqual(data, basic)
        finally:
            shutil.rmtree(tmpdir)

    def test_revoked(self):
        self.maxDiff = None

        with freeze_time(timestamps['everything_valid']) as frozen_timestamp:
            revoked_timestamp = datetime.utcnow().strftime(self.timeformat)
            cert = self.certs['ecc-cert']
            cert.revoke()

            self.assertIndex(expected=revoked_first, ca=self.cas['ecc'], revoked=revoked_timestamp)

            frozen_timestamp.tick(timedelta(seconds=3600))

            revoked_timestamp = datetime.utcnow().strftime(self.timeformat)
            cert.revoke('unspecified')
            self.assertIndex(expected=revoked_second, ca=self.cas['ecc'], revoked=revoked_timestamp)
