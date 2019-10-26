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

from __future__ import unicode_literals

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

from django.conf.urls import url
from django.core.cache import cache
from django.test import Client
from django.urls import reverse

from freezegun import freeze_time

from ..views import CertificateRevocationListView
from .base import DjangoCAWithCertTestCase
from .base import DjangoCAWithGeneratedCAsTestCase
from .base import override_settings
from .base import override_tmpcadir

urlpatterns = [
    url(r'^crl/(?P<serial>[0-9A-F:]+)/$', CertificateRevocationListView.as_view(), name='default'),
    url(r'^full/(?P<serial>[0-9A-F:]+)/$', CertificateRevocationListView.as_view(scope=None), name='full'),
    url(r'^adv/(?P<serial>[0-9A-F:]+)/$',
        CertificateRevocationListView.as_view(
            content_type='text/plain',
            digest=hashes.MD5(),
            expires=321,
            type=Encoding.PEM,
        ),
        name='advanced'),
    url(r'^crl/ca/(?P<serial>[0-9A-F:]+)/$', CertificateRevocationListView.as_view(
        scope='ca', type=Encoding.PEM
    ), name='ca_crl'),
    url(r'^crl/dep-ca/(?P<serial>[0-9A-F:]+)/$', CertificateRevocationListView.as_view(ca_crl=True),
        name='deprecated-ca'),
    url(r'^crl/dep-user/(?P<serial>[0-9A-F:]+)/$', CertificateRevocationListView.as_view(ca_crl=False),
        name='deprecated-user'),
]


# CRL code complains about 512 bit keys
@override_settings(ROOT_URLCONF=__name__, CA_MIN_KEY_SIZE=1024)
@freeze_time('2019-04-14 12:26:00')
class GenericCRLViewTests(DjangoCAWithCertTestCase):
    def setUp(self):
        super(GenericCRLViewTests, self).setUp()
        self.ca = self.cas['child']
        self.client = Client()

    def tearDown(self):
        cache.clear()

    @override_tmpcadir()
    def test_basic(self):
        # test the default view
        idp = self.get_idp(full_name=self.get_idp_full_name(self.ca), only_contains_user_certs=True)
        response = self.client.get(reverse('default', kwargs={'serial': self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/pkix-crl')
        self.assertCRL(response.content, encoding=Encoding.DER, expires=600, idp=idp)

        # revoke a certificate
        cert = self.certs['child-cert']
        cert.revoke()

        # fetch again - we should see a cached response
        response = self.client.get(reverse('default', kwargs={'serial': self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/pkix-crl')
        self.assertCRL(response.content, encoding=Encoding.DER, expires=600, idp=idp)

        # clear the cache and fetch again
        cache.clear()
        response = self.client.get(reverse('default', kwargs={'serial': self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/pkix-crl')
        self.assertCRL(response.content, encoding=Encoding.DER, expires=600, idp=idp, certs=[cert],
                       crl_number=1)

    @override_tmpcadir()
    def test_full_scope(self):
        full_name = 'http://localhost/crl'
        idp = self.get_idp(full_name=[x509.UniformResourceIdentifier(value=full_name)])

        self.ca.crl_url = full_name
        self.ca.save()

        response = self.client.get(reverse('full', kwargs={'serial': self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/pkix-crl')
        self.assertCRL(response.content, encoding=Encoding.DER, expires=600, idp=idp)

    @override_tmpcadir()
    def test_ca_crl(self):
        root = self.cas['root']
        child = self.cas['child']
        idp = self.get_idp(full_name=self.get_idp_full_name(root), only_contains_ca_certs=True)
        self.assertIsNotNone(root.key(password=None))

        response = self.client.get(reverse('ca_crl', kwargs={'serial': root.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/plain')
        self.assertCRL(response.content, expires=600, idp=idp, signer=root)

        child.revoke()
        child.save()

        # fetch again - we should see a cached response
        response = self.client.get(reverse('ca_crl', kwargs={'serial': root.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/plain')
        self.assertCRL(response.content, expires=600, idp=idp, signer=root)

        # clear the cache and fetch again
        cache.clear()
        response = self.client.get(reverse('ca_crl', kwargs={'serial': root.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/plain')
        self.assertCRL(response.content, expires=600, idp=idp, certs=[child], crl_number=1, signer=root)

    @override_tmpcadir()
    def test_overwrite(self):
        idp = self.get_idp(full_name=self.get_idp_full_name(self.ca), only_contains_user_certs=True)
        response = self.client.get(reverse('advanced', kwargs={'serial': self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/plain')
        self.assertCRL(response.content, expires=321, idp=idp, algorithm=hashes.MD5())

    @override_tmpcadir()
    def test_deprecated(self):
        response = self.client.get(reverse('deprecated-ca', kwargs={'serial': self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/pkix-crl')
        idp = self.get_idp(full_name=self.get_idp_full_name(self.ca), only_contains_ca_certs=True)
        self.assertCRL(response.content, encoding=Encoding.DER, expires=600, idp=idp)

        response = self.client.get(reverse('deprecated-user', kwargs={'serial': self.ca.serial}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/pkix-crl')
        idp = self.get_idp(full_name=self.get_idp_full_name(self.ca), only_contains_user_certs=True)
        self.assertCRL(response.content, encoding=Encoding.DER, expires=600, idp=idp)


@override_settings(USE_TZ=True)
class GenericCRLWithTZViewTests(GenericCRLViewTests):
    pass


class GenericCAIssuersViewTests(DjangoCAWithGeneratedCAsTestCase):
    def test_view(self):
        client = Client()

        for name, ca in self.cas.items():
            url = reverse('django_ca:issuer', kwargs={'serial': ca.root.serial})
            resp = client.get(url)
            self.assertEqual(resp['Content-Type'], 'application/pkix-cert')
            self.assertEqual(resp.content, ca.root.x509.public_bytes(encoding=Encoding.DER))
