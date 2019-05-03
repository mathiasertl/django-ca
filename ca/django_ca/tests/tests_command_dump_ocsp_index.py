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

from freezegun import freeze_time

from .. import ca_settings
from .base import DjangoCAWithCertTestCase
from .base import certs
from .base import override_settings
from .base import override_tmpcadir
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

file = """V\t190418000000Z\t\t5A1BA263A1E4D8D14D826046D38FE0C3A5B3E489\tunknown\t/C=AT/ST=Vienna/L=Vienna/OU=Fachschaft Informatik/CN=host1.example.com
V\t190418000000Z\t\t4E2B01C48BCC1F7194128864680CAA04D3F8BB45\tunknown\t/C=AT/ST=Vienna/L=Vienna/OU=Fachschaft Informatik/CN=host2.example.com
V\t190418000000Z\t\t32A7B08E88A21AEC05C8BA18D78BD935459D82FA\tunknown\t/C=AT/ST=Vienna/L=Vienna/OU=Fachschaft Informatik/CN=host3.example.com
V\t201016000000Z\t\t4EA5A0D119212EAB3D5639FABDD0A75BCC35E4D9\tunknown\t/CN=ocsp.ca.example.com
V\t201016000000Z\t\t336163E1DDD7379B77891D949212B4177413E114\tunknown\t/CN=all-extensions.example.com
V\t201025000000Z\t\t230BA643C4A7D749D5992DE350CAA64283EAE0B4\tunknown\t/C=AT/ST=Vienna/L=Vienna/OU=Fachschaft Informatik/CN=no-extensions.example.com
V\t280801235959Z\t\t7DD9FE07CFA81EB7107967FBA78934C6\tunknown\t/C=US/O=VeriSign, Inc./OU=Class 3 Public Primary Certification Authority - G2/OU=(c) 1998 VeriSign, Inc. - For authorized use only/OU=VeriSign Trust Network
V\t190124235959Z\t\t92529ABD85F0A6A4D6C53FD1C91011C1\tunknown\t/OU=Domain Control Validated/OU=PositiveSSL Multi-Domain/CN=sni24142.cloudflaressl.com
E\t181107091521Z\t\t4F578979F4E1B041ABA5831469B100BCF65\tunknown\t/CN=jabber.at
V\t190418100401Z\t\tC5D5BD0D2EE5FD65\tunknown\t/OU=Domain Control Validated/CN=derstandard.at
"""  # NOQA

expired = """E\t190418000000Z\t\t5A1BA263A1E4D8D14D826046D38FE0C3A5B3E489\tunknown\t/C=AT/ST=Vienna/L=Vienna/OU=Fachschaft Informatik/CN=host1.example.com
E\t190418000000Z\t\t4E2B01C48BCC1F7194128864680CAA04D3F8BB45\tunknown\t/C=AT/ST=Vienna/L=Vienna/OU=Fachschaft Informatik/CN=host2.example.com
E\t190418000000Z\t\t32A7B08E88A21AEC05C8BA18D78BD935459D82FA\tunknown\t/C=AT/ST=Vienna/L=Vienna/OU=Fachschaft Informatik/CN=host3.example.com
E\t201016000000Z\t\t4EA5A0D119212EAB3D5639FABDD0A75BCC35E4D9\tunknown\t/CN=ocsp.ca.example.com
E\t201016000000Z\t\t336163E1DDD7379B77891D949212B4177413E114\tunknown\t/CN=all-extensions.example.com
E\t201025000000Z\t\t230BA643C4A7D749D5992DE350CAA64283EAE0B4\tunknown\t/C=AT/ST=Vienna/L=Vienna/OU=Fachschaft Informatik/CN=no-extensions.example.com
V\t280801235959Z\t\t7DD9FE07CFA81EB7107967FBA78934C6\tunknown\t/C=US/O=VeriSign, Inc./OU=Class 3 Public Primary Certification Authority - G2/OU=(c) 1998 VeriSign, Inc. - For authorized use only/OU=VeriSign Trust Network
E\t190124235959Z\t\t92529ABD85F0A6A4D6C53FD1C91011C1\tunknown\t/OU=Domain Control Validated/OU=PositiveSSL Multi-Domain/CN=sni24142.cloudflaressl.com
E\t181107091521Z\t\t4F578979F4E1B041ABA5831469B100BCF65\tunknown\t/CN=jabber.at
E\t190418100401Z\t\tC5D5BD0D2EE5FD65\tunknown\t/OU=Domain Control Validated/CN=derstandard.at
"""  # NOQA

revoked_first = """R\t190418000000Z\t181220231300Z\t5A1BA263A1E4D8D14D826046D38FE0C3A5B3E489\tunknown\t/C=AT/ST=Vienna/L=Vienna/OU=Fachschaft Informatik/CN=host1.example.com
V\t190418000000Z\t\t4E2B01C48BCC1F7194128864680CAA04D3F8BB45\tunknown\t/C=AT/ST=Vienna/L=Vienna/OU=Fachschaft Informatik/CN=host2.example.com
V\t190418000000Z\t\t32A7B08E88A21AEC05C8BA18D78BD935459D82FA\tunknown\t/C=AT/ST=Vienna/L=Vienna/OU=Fachschaft Informatik/CN=host3.example.com
V\t201016000000Z\t\t4EA5A0D119212EAB3D5639FABDD0A75BCC35E4D9\tunknown\t/CN=ocsp.ca.example.com
V\t201016000000Z\t\t336163E1DDD7379B77891D949212B4177413E114\tunknown\t/CN=all-extensions.example.com
V\t201025000000Z\t\t230BA643C4A7D749D5992DE350CAA64283EAE0B4\tunknown\t/C=AT/ST=Vienna/L=Vienna/OU=Fachschaft Informatik/CN=no-extensions.example.com
V\t280801235959Z\t\t7DD9FE07CFA81EB7107967FBA78934C6\tunknown\t/C=US/O=VeriSign, Inc./OU=Class 3 Public Primary Certification Authority - G2/OU=(c) 1998 VeriSign, Inc. - For authorized use only/OU=VeriSign Trust Network
V\t190124235959Z\t\t92529ABD85F0A6A4D6C53FD1C91011C1\tunknown\t/OU=Domain Control Validated/OU=PositiveSSL Multi-Domain/CN=sni24142.cloudflaressl.com
E\t181107091521Z\t\t4F578979F4E1B041ABA5831469B100BCF65\tunknown\t/CN=jabber.at
V\t190418100401Z\t\tC5D5BD0D2EE5FD65\tunknown\t/OU=Domain Control Validated/CN=derstandard.at
"""  # NOQA

revoked_second = """R\t190418000000Z\t181220231300Z,unspecified\t5A1BA263A1E4D8D14D826046D38FE0C3A5B3E489\tunknown\t/C=AT/ST=Vienna/L=Vienna/OU=Fachschaft Informatik/CN=host1.example.com
V\t190418000000Z\t\t4E2B01C48BCC1F7194128864680CAA04D3F8BB45\tunknown\t/C=AT/ST=Vienna/L=Vienna/OU=Fachschaft Informatik/CN=host2.example.com
V\t190418000000Z\t\t32A7B08E88A21AEC05C8BA18D78BD935459D82FA\tunknown\t/C=AT/ST=Vienna/L=Vienna/OU=Fachschaft Informatik/CN=host3.example.com
V\t201016000000Z\t\t4EA5A0D119212EAB3D5639FABDD0A75BCC35E4D9\tunknown\t/CN=ocsp.ca.example.com
V\t201016000000Z\t\t336163E1DDD7379B77891D949212B4177413E114\tunknown\t/CN=all-extensions.example.com
V\t201025000000Z\t\t230BA643C4A7D749D5992DE350CAA64283EAE0B4\tunknown\t/C=AT/ST=Vienna/L=Vienna/OU=Fachschaft Informatik/CN=no-extensions.example.com
V\t280801235959Z\t\t7DD9FE07CFA81EB7107967FBA78934C6\tunknown\t/C=US/O=VeriSign, Inc./OU=Class 3 Public Primary Certification Authority - G2/OU=(c) 1998 VeriSign, Inc. - For authorized use only/OU=VeriSign Trust Network
V\t190124235959Z\t\t92529ABD85F0A6A4D6C53FD1C91011C1\tunknown\t/OU=Domain Control Validated/OU=PositiveSSL Multi-Domain/CN=sni24142.cloudflaressl.com
E\t181107091521Z\t\t4F578979F4E1B041ABA5831469B100BCF65\tunknown\t/CN=jabber.at
V\t190418100401Z\t\tC5D5BD0D2EE5FD65\tunknown\t/OU=Domain Control Validated/CN=derstandard.at
"""  # NOQA


@freeze_time("2018-12-20 23:13:00")
@override_settings()
class OCSPIndexTestCase(DjangoCAWithCertTestCase):
    def assertIndex(self, certs=None, ca=None, expected=''):
        if certs is None:
            certs = self.certs
        if ca is None:
            ca = self.cas['child']

        stdout, stderr = self.cmd('dump_ocsp_index', ca=ca)
        self.assertEqual(stdout, expected)
        self.assertEqual(stderr, '')

    @freeze_time(timestamps['everything_valid'])
    def test_basic(self):
        self.maxDiff = None
        self.assertIndex(expected=basic)

    @override_tmpcadir()
    def test_file(self):
        path = os.path.join(ca_settings.CA_DIR, 'ocsp-index.txt')

        stdout, stderr = self.cmd('dump_ocsp_index', path)
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')

        with open(path) as stream:
            self.assertEqual(stream.read(), file)

    @freeze_time("2020-12-20 23:13:00")
    def test_expired(self):
        self.maxDiff = None
        self.assertIndex(expected=expired)

    def test_revoked(self):
        self.maxDiff = None
        self.cert.revoke()

        self.assertIndex(expected=revoked_first)

        self.cert.revoke('unspecified')

        self.assertIndex(expected=revoked_second)
