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

from datetime import timedelta

from django.utils import timezone

from ..models import CertificateAuthority
from .base import DjangoCATestCase
from .base import certs
from .base import override_settings

expected = """{dsa[serial_colons]} - {dsa[name]}{dsa_state}
{ecc[serial_colons]} - {ecc[name]}{ecc_state}
{pwd[serial_colons]} - {pwd[name]}{pwd_state}
{root[serial_colons]} - {root[name]}{root_state}
{child[serial_colons]} - {child[name]}{child_state}
"""


class ListCertsTestCase(DjangoCATestCase):
    def setUp(self):
        super(ListCertsTestCase, self).setUp()
        self.load_usable_cas()

    def assertOutput(self, output, expected, **context):
        context.update(certs)
        for ca_name in self.cas:
            context.setdefault('%s_state' % ca_name, '')
        self.assertEqual(output, expected.format(**context))

    def test_all_cas(self):
        self.load_all_cas()
        stdout, stderr = self.cmd('list_cas')
        self.assertEqual(stdout, """{dsa[serial_colons]} - {dsa[name]}
{ecc[serial_colons]} - {ecc[name]}
{pwd[serial_colons]} - {pwd[name]}
{root[serial_colons]} - {root[name]}
{child[serial_colons]} - {child[name]}
{letsencrypt_x1[serial_colons]} - {letsencrypt_x1[name]}
{letsencrypt_x3[serial_colons]} - {letsencrypt_x3[name]}
{dst_root_x3[serial_colons]} - {dst_root_x3[name]}
{google_g3[serial_colons]} - {google_g3[name]}
{globalsign_r2_root[serial_colons]} - {globalsign_r2_root[name]}
{trustid_server_a52[serial_colons]} - {trustid_server_a52[name]}
{rapidssl_g3[serial_colons]} - {rapidssl_g3[name]}
{geotrust[serial_colons]} - {geotrust[name]}
{startssl_class2[serial_colons]} - {startssl_class2[name]}
{digicert_sha2[serial_colons]} - {digicert_sha2[name]}
{globalsign_dv[serial_colons]} - {globalsign_dv[name]}
{comodo_ev[serial_colons]} - {comodo_ev[name]}
{globalsign[serial_colons]} - {globalsign[name]}
{digicert_ha_intermediate[serial_colons]} - {digicert_ha_intermediate[name]}
{comodo_dv[serial_colons]} - {comodo_dv[name]}
{startssl_class3[serial_colons]} - {startssl_class3[name]}
{godaddy_g2_intermediate[serial_colons]} - {godaddy_g2_intermediate[name]}
{digicert_ev_root[serial_colons]} - {digicert_ev_root[name]}
{digicert_global_root[serial_colons]} - {digicert_global_root[name]}
{identrust_root_1[serial_colons]} - {identrust_root_1[name]}
{startssl_root[serial_colons]} - {startssl_root[name]}
{godaddy_g2_root[serial_colons]} - {godaddy_g2_root[name]}
{comodo[serial_colons]} - {comodo[name]}
""".format(**certs))
        self.assertEqual(stderr, '')

    def test_no_cas(self):
        CertificateAuthority.objects.all().delete()
        stdout, stderr = self.cmd('list_cas')
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')

    def test_basic(self):
        stdout, stderr = self.cmd('list_cas')
        self.assertOutput(stdout, expected)
        self.assertEqual(stderr, '')

    def test_disabled(self):
        ca = self.cas['root']
        ca.enabled = False
        ca.save()

        stdout, stderr = self.cmd('list_cas')
        self.assertOutput(stdout, expected, root_state=' (disabled)')
        self.assertEqual(stderr, '')

    def test_tree(self):
        stdout, stderr = self.cmd('list_cas', tree=True)
        self.assertEqual(stdout, """{dsa[serial_colons]} - {dsa[name]}
{ecc[serial_colons]} - {ecc[name]}
{pwd[serial_colons]} - {pwd[name]}
{root[serial_colons]} - {root[name]}
└───{child[serial_colons]} - {child[name]}
""".format(**certs))
        self.assertEqual(stderr, '')

        # manually create Certificate objects
        expires = timezone.now() + timedelta(days=3)
        valid_from = timezone.now() - timedelta(days=3)
        root = self.cas['root']
        child3 = CertificateAuthority.objects.create(name='child3', serial='child3',
                                                     parent=root, expires=expires, valid_from=valid_from)
        CertificateAuthority.objects.create(name='child4', serial='child4', parent=root, expires=expires,
                                            valid_from=valid_from)
        CertificateAuthority.objects.create(name='child3.1', serial='child3.1', parent=child3,
                                            expires=expires, valid_from=valid_from)

        stdout, stderr = self.cmd('list_cas', tree=True)
        context = {}
        context.update(certs)
        self.assertEqual(stdout, """{dsa[serial_colons]} - {dsa[name]}
{ecc[serial_colons]} - {ecc[name]}
{pwd[serial_colons]} - {pwd[name]}
{root[serial_colons]} - {root[name]}
│───ch:il:d3 - child3
│   └───ch:il:d3:.1 - child3.1
│───ch:il:d4 - child4
└───{child[serial_colons]} - {child[name]}
""".format(**context))


@override_settings(USE_TZ=True)
class ListCertsWithTZTestCase(ListCertsTestCase):
    pass
