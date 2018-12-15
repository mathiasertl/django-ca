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

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from .. import ca_settings
from ..extensions import BasicConstraints
from ..extensions import KeyUsage
from ..models import CertificateAuthority
from ..subject import Subject
from .base import DjangoCATestCase
from .base import override_settings
from .base import override_tmpcadir


@override_settings(CA_MIN_KEY_SIZE=1024)
class CertificateAuthorityQuerySetTestCase(DjangoCATestCase):
    @override_tmpcadir()
    def test_basic(self):
        key_size = ca_settings.CA_MIN_KEY_SIZE
        ca = CertificateAuthority.objects.init(
            name='Root CA', key_size=key_size, key_type='RSA', algorithm=hashes.SHA256(),
            expires=self.expires(720), parent=None, pathlen=0, subject=Subject([('CN', 'ca.example.com')]))

        self.assertEqual(ca.name, 'Root CA')

        # verify private key properties
        self.assertEqual(ca.key(None).key_size, 1024)
        self.assertIsInstance(ca.key(None).public_key(), RSAPublicKey)

        # verity public key propertiesa
        self.assertBasic(ca.x509)
        self.assertEqual(ca.subject, Subject({'CN': 'ca.example.com'}))

        # verify X509 properties
        self.assertEqual(ca.basic_constraints, BasicConstraints('critical,CA:TRUE,pathlen=0'))
        self.assertEqual(ca.key_usage, KeyUsage('critical,cRLSign,keyCertSign'))
        self.assertIsNone(ca.subject_alternative_name, None)

        self.assertIsNone(ca.extended_key_usage)
        self.assertIsNone(ca.tls_feature)
        self.assertIsNone(ca.issuer_alternative_name)

    @override_tmpcadir()
    def test_pathlen(self):
        key_size = ca_settings.CA_MIN_KEY_SIZE
        kwargs = dict(
            key_size=key_size, key_type='RSA', algorithm=hashes.SHA256(), expires=self.expires(720),
            parent=None, subject=Subject([('CN', 'ca.example.com')]))

        ca = CertificateAuthority.objects.init(name='1', **kwargs)
        self.assertEqual(ca.basic_constraints, BasicConstraints('critical,CA:TRUE'))

        ca = CertificateAuthority.objects.init(pathlen=0, name='2', **kwargs)
        self.assertEqual(ca.basic_constraints, BasicConstraints('critical,CA:TRUE,pathlen=0'))
        ca = CertificateAuthority.objects.init(pathlen=2, name='3', **kwargs)
        self.assertEqual(ca.basic_constraints, BasicConstraints('critical,CA:TRUE,pathlen=2'))

    @override_tmpcadir()
    def test_parent(self):
        key_size = ca_settings.CA_MIN_KEY_SIZE

        kwargs = dict(
            key_size=key_size, key_type='RSA', algorithm=hashes.SHA256(), expires=self.expires(720),
            subject=Subject([('CN', 'ca.example.com')]))

        parent = CertificateAuthority.objects.init(name='Root', parent=None, pathlen=1, **kwargs)
        child = CertificateAuthority.objects.init(name='Child', parent=parent, pathlen=0, **kwargs)

        self.assertEqual(child.authority_key_identifier.value, parent.subject_key_identifier.value)

    @override_tmpcadir()
    def test_key_size(self):
        kwargs = dict(
            name='Root CA', key_type='RSA', algorithm='sha256', expires=self.expires(720),
            parent=None, pathlen=0, subject={'CN': 'ca.example.com', })

        key_size = ca_settings.CA_MIN_KEY_SIZE

        with self.assertRaisesRegex(ValueError, r'^3072: Key size must be a power of two$'):
            CertificateAuthority.objects.init(key_size=key_size * 3, **kwargs)
        with self.assertRaisesRegex(ValueError, r'^1025: Key size must be a power of two$'):
            CertificateAuthority.objects.init(key_size=key_size + 1, **kwargs)
        with self.assertRaisesRegex(ValueError, r'^512: Key size must be least 1024 bits$'):
            CertificateAuthority.objects.init(key_size=int(key_size / 2), **kwargs)
        with self.assertRaisesRegex(ValueError, r'^256: Key size must be least 1024 bits$'):
            CertificateAuthority.objects.init(key_size=int(key_size / 4), **kwargs)
