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

from freezegun import freeze_time

from .. import ca_settings
from ..extensions import BasicConstraints
from ..extensions import KeyUsage
from ..models import Certificate
from ..models import CertificateAuthority
from ..subject import Subject
from .base import DjangoCATestCase
from .base import DjangoCAWithGeneratedCertsTestCase
from .base import override_settings
from .base import override_tmpcadir
from .base import timestamps


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
        self.assertEqual(ca.basic_constraints,
                         BasicConstraints({'critical': True, 'value': {'ca': True, 'pathlen': 0}}))
        self.assertEqual(ca.key_usage, KeyUsage({'critical': True, 'value': ['cRLSign', 'keyCertSign']}))
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
        self.assertEqual(ca.basic_constraints, BasicConstraints({'critical': True, 'value': {'ca': True}}))

        ca = CertificateAuthority.objects.init(pathlen=0, name='2', **kwargs)
        self.assertEqual(ca.basic_constraints,
                         BasicConstraints({'critical': True, 'value': {'ca': True, 'pathlen': 0}}))

        ca = CertificateAuthority.objects.init(pathlen=2, name='3', **kwargs)
        self.assertEqual(ca.basic_constraints,
                         BasicConstraints({'critical': True, 'value': {'ca': True, 'pathlen': 2}}))

    @override_tmpcadir()
    def test_parent(self):
        key_size = ca_settings.CA_MIN_KEY_SIZE

        kwargs = dict(
            key_size=key_size, key_type='RSA', algorithm=hashes.SHA256(), expires=self.expires(720),
            subject=Subject([('CN', 'ca.example.com')]))

        parent = CertificateAuthority.objects.init(name='Root', parent=None, pathlen=1, **kwargs)
        child = CertificateAuthority.objects.init(name='Child', parent=parent, pathlen=0, **kwargs)

        self.assertAuthorityKeyIdentifier(parent, child)

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

    def test_enabled_disabled(self):
        self.load_usable_cas()
        name = 'root'
        self.assertCountEqual(CertificateAuthority.objects.enabled(), self.cas.values())
        self.assertCountEqual(CertificateAuthority.objects.disabled(), [])

        self.cas[name].enabled = False
        self.cas[name].save()

        self.assertCountEqual(CertificateAuthority.objects.enabled(),
                              [c for c in self.cas.values() if c.name != name])
        self.assertCountEqual(CertificateAuthority.objects.disabled(), [self.cas['root']])

    def test_valid(self):
        self.load_usable_cas()

        with freeze_time(timestamps['before_cas']):
            self.assertCountEqual(CertificateAuthority.objects.valid(), [])
            self.assertCountEqual(CertificateAuthority.objects.usable(), [])
            self.assertCountEqual(CertificateAuthority.objects.invalid(), self.cas.values())

        with freeze_time(timestamps['before_child']):
            valid = [c for c in self.cas.values() if c.name != 'child']
            self.assertCountEqual(CertificateAuthority.objects.valid(), valid)
            self.assertCountEqual(CertificateAuthority.objects.usable(), valid)
            self.assertCountEqual(CertificateAuthority.objects.invalid(), [self.cas['child']])

        with freeze_time(timestamps['after_child']):
            self.assertCountEqual(CertificateAuthority.objects.valid(), self.cas.values())
            self.assertCountEqual(CertificateAuthority.objects.usable(), self.cas.values())
            self.assertCountEqual(CertificateAuthority.objects.invalid(), [])

        with freeze_time(timestamps['cas_expired']):
            self.assertCountEqual(CertificateAuthority.objects.valid(), [])
            self.assertCountEqual(CertificateAuthority.objects.usable(), [])
            self.assertCountEqual(CertificateAuthority.objects.invalid(), self.cas.values())


class CertificateQuerysetTestCase(DjangoCAWithGeneratedCertsTestCase):
    def assertQuerySet(self, qs, *items):
        self.assertCountEqual(list(qs), items)

    def test_validity(self):
        with freeze_time(timestamps['everything_valid']):
            self.assertQuerySet(Certificate.objects.expired())
            self.assertQuerySet(Certificate.objects.not_yet_valid())
            self.assertQuerySet(Certificate.objects.valid(), *self.certs.values())

        with freeze_time(timestamps['everything_expired']):
            self.assertQuerySet(Certificate.objects.expired(), *self.certs.values())
            self.assertQuerySet(Certificate.objects.not_yet_valid())
            self.assertQuerySet(Certificate.objects.valid())

        with freeze_time(timestamps['before_everything']):
            self.assertQuerySet(Certificate.objects.expired())
            self.assertQuerySet(Certificate.objects.not_yet_valid(), *self.certs.values())
            self.assertQuerySet(Certificate.objects.valid())

        expired = [
            self.certs['root-cert'],
            self.certs['child-cert'],
            self.certs['ecc-cert'],
            self.certs['dsa-cert'],
            self.certs['pwd-cert'],
        ]
        valid = [c for c in self.certs.values() if c not in expired]
        with freeze_time(timestamps['ca_certs_expired']):
            self.assertQuerySet(Certificate.objects.expired(), *expired)
            self.assertQuerySet(Certificate.objects.not_yet_valid())
            self.assertQuerySet(Certificate.objects.valid(), *valid)
