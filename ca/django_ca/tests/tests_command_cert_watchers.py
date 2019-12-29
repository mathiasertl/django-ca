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

from .base import DjangoCAWithGeneratedCertsTestCase


class CertWatchersTestCase(DjangoCAWithGeneratedCertsTestCase):
    def test_basic(self):
        cert = self.certs['root-cert']
        stdout, stderr = self.cmd('cert_watchers', cert.serial, add=['user-added@example.com'])
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')
        self.assertTrue(cert.watchers.filter(mail='user-added@example.com').exists())

        # remove user again
        stdout, stderr = self.cmd('cert_watchers', cert.serial, rm=['user-added@example.com'])
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')
        self.assertFalse(cert.watchers.filter(mail='user-added@example.com').exists())

        # removing again does nothing, but doesn't throw an error either
        stdout, stderr = self.cmd('cert_watchers', cert.serial, rm=['user-added@example.com'])
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')
        self.assertFalse(cert.watchers.filter(mail='user-added@example.com').exists())
