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

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

from django.conf.urls import url
from django.core.cache import cache
from django.test import Client
from django.urls import reverse

from ..models import Certificate
from ..views import CertificateRevocationListView
from .base import DjangoCAWithCertTestCase
from .base import override_settings
from .base import override_tmpcadir

urlpatterns = [
    url(r'^crl/(?P<serial>[0-9A-F:]+)/$', CertificateRevocationListView.as_view(),
        name='default'),
    url(r'^adv/(?P<serial>[0-9A-F:]+)/$',
        CertificateRevocationListView.as_view(
            content_type='text/plain',
            digest=hashes.MD5(),
            expires=321,
            type=Encoding.PEM,
        ),
        name='advanced'),
    url(r'^crl/ca/(?P<serial>[0-9A-F:]+)/$', CertificateRevocationListView.as_view(
        ca_crl=True, type=Encoding.PEM
    ), name='ca_crl'),
]


# CRL code complains about 512 bit keys
@override_settings(ROOT_URLCONF=__name__, CA_MIN_KEY_SIZE=1024)
class GenericCRLViewTests(DjangoCAWithCertTestCase):
    def setUp(self):
        self.client = Client()
        super(GenericCRLViewTests, self).setUp()

    def tearDown(self):
        cache.clear()

    @override_tmpcadir()
    def test_basic(self):
        # test the default view
        response = self.client.get(reverse('default', kwargs={'serial': self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/pkix-crl')

        crl = x509.load_der_x509_crl(response.content, default_backend())
        self.assertIsInstance(crl.signature_hash_algorithm, hashes.SHA512)
        self.assertEqual(list(crl), [])

        # revoke a certificate
        cert = Certificate.objects.get(serial=self.cert.serial)
        cert.revoke()

        # fetch again - we should see a cached response
        response = self.client.get(reverse('default', kwargs={'serial': self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/pkix-crl')
        crl = x509.load_der_x509_crl(response.content, default_backend())
        self.assertIsInstance(crl.signature_hash_algorithm, hashes.SHA512)
        self.assertEqual(list(crl), [])

        # clear the cache and fetch again
        cache.clear()
        response = self.client.get(reverse('default', kwargs={'serial': self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/pkix-crl')
        crl = x509.load_der_x509_crl(response.content, default_backend())
        self.assertIsInstance(crl.signature_hash_algorithm, hashes.SHA512)
        self.assertEqual(len(list(crl)), 1)
        self.assertEqual(crl[0].serial_number, cert.x509.serial_number)

    @override_settings(USE_TZ=True)
    def test_basic_with_use_tz(self):
        self.test_basic()

    @override_tmpcadir()
    def test_ca_crl(self):
        child = self.create_ca(name='child', parent=self.ca)
        self.assertIsNotNone(child.key(password=None))

        response = self.client.get(reverse('ca_crl', kwargs={'serial': self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/plain')
        crl = x509.load_pem_x509_crl(response.content, default_backend())
        self.assertIsInstance(crl.signature_hash_algorithm, hashes.SHA512)
        self.assertEqual(list(crl), [])

        child.revoke()
        child.save()

        # fetch again - we should see a cached response
        response = self.client.get(reverse('ca_crl', kwargs={'serial': self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/plain')
        crl = x509.load_pem_x509_crl(response.content, default_backend())
        self.assertIsInstance(crl.signature_hash_algorithm, hashes.SHA512)
        self.assertEqual(len(list(crl)), 0)

        # clear the cache and fetch again
        cache.clear()
        response = self.client.get(reverse('ca_crl', kwargs={'serial': self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/plain')
        crl = x509.load_pem_x509_crl(response.content, default_backend())
        self.assertIsInstance(crl.signature_hash_algorithm, hashes.SHA512)
        self.assertEqual(len(list(crl)), 1)
        self.assertEqual(crl[0].serial_number, child.x509.serial_number)

    @override_tmpcadir()
    def test_overwrite(self):
        response = self.client.get(reverse('advanced', kwargs={'serial': self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/plain')

        crl = x509.load_pem_x509_crl(response.content, default_backend())
        self.assertIsInstance(crl.signature_hash_algorithm, hashes.MD5)

        # parse Last/Next Update to see if they match 321 seconds
        self.assertEqual((crl.next_update - crl.last_update).seconds, 321)

    @override_settings(USE_TZ=True)
    def test_overwrite_with_use_tz(self):
        self.test_overwrite()
