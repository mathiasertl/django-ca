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

import re

import dateparser

from OpenSSL import crypto

from django.conf.urls import url
from django.core.cache import cache
from django.core.urlresolvers import reverse
from django.test import Client
from django.utils.encoding import force_text

from ..views import CertificateRevocationListView
from ..models import Certificate
from .base import DjangoCAWithCertTestCase
from .base import override_tmpcadir

urlpatterns = [
    url(r'^crl/(?P<serial>[0-9A-F:]+)/$', CertificateRevocationListView.as_view(), 
        name='default'),
    url(r'^adv/(?P<serial>[0-9A-F:]+)/$', 
        CertificateRevocationListView.as_view(
            content_type='text/plain',
            digest='md5',
            expires=321,
            type=crypto.FILETYPE_TEXT,
        ), 
        name='advanced'),
]

# CRL code complains about 512 bit keys
@override_tmpcadir(ROOT_URLCONF=__name__, CA_MIN_KEY_SIZE=1024)
class GenericCRLViewTests(DjangoCAWithCertTestCase):
    def setUp(self):
        self.client = Client()
        super(GenericCRLViewTests, self).setUp()

    def test_basic(self):
        # test the default view
        response = self.client.get(reverse('default', kwargs={'serial': self.ca.serial}))
        self.assertEqual(response.status_code, 200)

        crl = crypto.load_crl(crypto.FILETYPE_ASN1, response.content)
        self.assertEqual(response['Content-Type'], 'application/pkix-crl')
        self.assertIsNone(crl.get_revoked())

        # revoke a certificate
        cert = Certificate.objects.get(serial=self.cert.serial)
        cert.revoke()

        # fetch again - we should see a cached response
        response = self.client.get(reverse('default', kwargs={'serial': self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/pkix-crl')
        crl = crypto.load_crl(crypto.FILETYPE_ASN1, response.content)
        self.assertIsNone(crl.get_revoked())

        # clear the cache and fetch again
        cache.clear()
        response = self.client.get(reverse('default', kwargs={'serial': self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/pkix-crl')
        crl = crypto.load_crl(crypto.FILETYPE_ASN1, response.content)
        self.assertEqual(len(crl.get_revoked()), 1)

    def test_overwrite(self):
        response = self.client.get(reverse('advanced', kwargs={'serial': self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/plain')

        # OpenSSL does not allow loading of TEXT CRLs :-(
        #crl = crypto.load_crl(crypto.FILETYPE_TEXT, response.content)
        #self.assertIsNone(crl.get_revoked())

        # The CRL object does not give any access to how the CRL was signed etc, so we do some
        # primitive string matching
        content = force_text(response.content)
        self.assertIn('Signature Algorithm: md5WithRSAEncryption', content)
        self.assertIn('No Revoked Certificates.', content)

        # parse Last/Next Update to see if they match 321 seconds
        last = dateparser.parse(re.search('Last Update: (.*)', content).groups()[0])
        next = dateparser.parse(re.search('Next Update: (.*)', content).groups()[0])
        self.assertEqual((next - last).seconds, 321)
