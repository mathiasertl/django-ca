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

"""Test querysets."""

from OpenSSL import crypto

from django_ca.tests.base import DjangoCATestCase

from .. import ca_settings
from ..models import CertificateAuthority
from .base import override_tmpcadir


@override_tmpcadir(CA_MIN_KEY_SIZE=1024)
class CertificateAuthorityQuerySetTestCase(DjangoCATestCase):
    def test_basic(self):
        key_size = ca_settings.CA_MIN_KEY_SIZE
        ca = CertificateAuthority.objects.init(
            name='Root CA', key_size=key_size, key_type='RSA', algorithm='sha256',
            expires=self.expires(720), parent=None, pathlen=0, subject={'CN': 'ca.example.com', })

        self.assertEqual(ca.name, 'Root CA')

        # verify private key properties
        self.assertTrue(ca.key.check())
        self.assertEqual(ca.key.bits(), 1024)
        self.assertEqual(ca.key.type(), crypto.TYPE_RSA)

        # verity public key properties
        self.assertEqual(ca.x509.get_signature_algorithm(), b'sha256WithRSAEncryption')
        self.assertEqual(ca.x509.get_subject().get_components(), [(b'CN', b'ca.example.com')])

        # verify X509 properties
        self.assertEqual(ca.basicConstraints(), 'critical,CA:TRUE, pathlen:0')
        self.assertEqual(ca.keyUsage(), 'critical,Certificate Sign, CRL Sign')
        self.assertEqual(ca.subjectAltName(), '')

        # TODO: What do LetsEncrypt, StartSSL and Gandi set for this?
        self.assertEqual(ca.extendedKeyUsage(), '')
#        self.assertEqual(ca.subjectKeyIdentifier(), 'DNS:ca.example.com')  # a serial
#        self.assertEqual(ca.authorityKeyIdentifier(), 'DNS:ca.example.com')  # a serial
        self.assertEqual(ca.issuerAltName(), '')

    def test_pathlen(self):
        key_size = ca_settings.CA_MIN_KEY_SIZE
        kwargs = dict(
            key_size=key_size, key_type='RSA', algorithm='sha256', expires=self.expires(720),
            parent=None, subject={'CN': 'ca.example.com', })

        ca = CertificateAuthority.objects.init(pathlen=False, name='1', **kwargs)
        self.assertEqual(ca.basicConstraints(), 'critical,CA:TRUE')

        ca = CertificateAuthority.objects.init(pathlen=0, name='2', **kwargs)
        self.assertEqual(ca.basicConstraints(), 'critical,CA:TRUE, pathlen:0')
        ca = CertificateAuthority.objects.init(pathlen=2, name='3', **kwargs)
        self.assertEqual(ca.basicConstraints(), 'critical,CA:TRUE, pathlen:2')

    def test_parent(self):
        key_size = ca_settings.CA_MIN_KEY_SIZE

        kwargs = dict(
            key_size=key_size, key_type='RSA', algorithm='sha256', expires=self.expires(720),
            subject={'CN': 'ca.example.com', })

        parent = CertificateAuthority.objects.init(name='Root', parent=None, pathlen=1, **kwargs)
        child = CertificateAuthority.objects.init(name='Child', parent=parent, pathlen=0, **kwargs)

        childAuthKeyId = child.authorityKeyIdentifier()
        self.assertEqual(childAuthKeyId, 'keyid:%s\n' % parent.subjectKeyIdentifier())

    def test_key_size(self):
        kwargs = dict(
            name='Root CA', key_type='RSA', algorithm='sha256', expires=self.expires(720),
            parent=None, pathlen=0, subject={'CN': 'ca.example.com', })

        key_size = ca_settings.CA_MIN_KEY_SIZE

        with self.assertRaises(RuntimeError):
            CertificateAuthority.objects.init(key_size=key_size * 3, **kwargs)
        with self.assertRaises(RuntimeError):
            CertificateAuthority.objects.init(key_size=key_size + 1, **kwargs)
        with self.assertRaises(RuntimeError):
            CertificateAuthority.objects.init(key_size=int(key_size / 2), **kwargs)
        with self.assertRaises(RuntimeError):
            CertificateAuthority.objects.init(key_size=int(key_size / 4), **kwargs)
