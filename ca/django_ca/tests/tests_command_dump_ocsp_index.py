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
from datetime import timedelta

from django.utils import timezone

from .. import ca_settings
from ..ocsp import date_format
from .base import DjangoCAWithCertTestCase
from .base import override_settings
from .base import override_tmpcadir


@override_settings(CA_MIN_KEY_SIZE=1024, CA_PROFILES={}, CA_DEFAULT_SUBJECT={})
class OCSPIndexTestCase(DjangoCAWithCertTestCase):
    def line(self, cert):
        revocation = ''
        if cert.expires < timezone.now():
            status = 'E'
        elif cert.revoked is True:
            status = 'R'
            revocation = cert.revoked_date.strftime(date_format)

            if cert.revoked_reason:
                revocation += ',%s' % cert.revoked_reason
        else:
            status = 'V'

        return '%s\t%s\t%s\t%s\tunknown\t%s' % (
            status,
            cert.x509.not_valid_after.strftime(date_format),
            revocation,
            cert.serial.replace(':', ''),
            cert.distinguishedName(),
        )

    def assertIndex(self, certs=None):
        if certs is None:
            certs = self.certs

        stdout, stderr = self.cmd('dump_ocsp_index')
        self.assertEqual(stdout, ''.join(['%s\n' % self.line(c) for c in certs]))
        self.assertEqual(stderr, '')

    def test_basic(self):
        self.assertIndex()

    @override_tmpcadir()
    def test_file(self):
        path = os.path.join(ca_settings.CA_DIR, 'ocsp-index.txt')

        stdout, stderr = self.cmd('dump_ocsp_index', path)
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')

        with open(path) as stream:
            self.assertEqual(stream.read(), ''.join(['%s\n' % self.line(c) for c in self.certs]))

    def test_expired(self):
        self.cert.expires = timezone.now() - timedelta(days=3)
        self.cert.save()

        self.assertIndex()

    def test_revoked(self):
        self.maxDiff = None
        self.cert.revoke()

        self.assertIndex()

        self.cert.revoke('unspecified')

        self.assertIndex()
