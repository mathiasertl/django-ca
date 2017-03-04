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

from datetime import timedelta

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from django.core.management.base import CommandError
from django.utils import six

from django_ca.models import CertificateAuthority
from django_ca.tests.base import DjangoCATestCase
from django_ca.tests.base import override_tmpcadir

from .. import ca_settings


class InitCATest(DjangoCATestCase):
    def init_ca(self, **kwargs):
        name = kwargs.pop('name', 'Test CA')
        kwargs.setdefault('key_size', ca_settings.CA_MIN_KEY_SIZE)
        return self.cmd('init_ca', name, '/C=AT/ST=Vienna/L=Vienna/O=Org/OU=OrgUnit/CN=%s' % name,
                        **kwargs)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_basic(self):
        out, err = self.init_ca()
        self.assertEqual(out, '')
        self.assertEqual(err, '')

        ca = CertificateAuthority.objects.first()
        self.assertEqual(ca.x509.get_signature_algorithm(), six.b('sha512WithRSAEncryption'))

        self.assertSubject(ca.x509c, {'C': 'AT', 'ST': 'Vienna', 'L': 'Vienna', 'O': 'Org',
                                      'OU': 'OrgUnit', 'CN': 'Test CA'})
        self.assertIssuer(ca, ca)
        self.assertAuthorityKeyIdentifier(ca, ca)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_arguments(self):
        out, err = self.init_ca(
            algorithm=hashes.SHA1(),
            key_type='DSA',
            key_size=1024,
            expires=self.expires(720),
            pathlen=3,
            issuer_url='http://issuer.ca.example.com',
            issuer_alt_name='http://ian.ca.example.com',
            crl_url=['http://crl.example.com'],
            ocsp_url='http://ocsp.example.com',
            ca_issuer_url='http://ca.issuer.ca.example.com',
            ca_crl_url=['http://ca.crl.example.com'],
            ca_ocsp_url='http://ca.ocsp.example.com',
            name_constraint=['permitted;DNS:.com'],
        )
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        ca = CertificateAuthority.objects.first()

        self.assertTrue(isinstance(ca.x509c.signature_hash_algorithm, hashes.SHA1))
        self.assertTrue(isinstance(ca.x509c.public_key(), dsa.DSAPublicKey))
        self.assertEqual(ca.crlDistributionPoints(), 'Full Name: URI:http://ca.crl.example.com')
        self.assertEqual(ca.authorityInfoAccess(),
                         'OCSP - URI:http://ca.ocsp.example.com\n'
                         'CA Issuers - URI:http://ca.issuer.ca.example.com\n')
        self.assertEqual(ca.nameConstraints(), 'critical,Permitted:\n  DNS:.com\n')
        self.assertEqual(ca.pathlen, 3)
        self.assertEqual(ca.issuer_url, 'http://issuer.ca.example.com')
        self.assertEqual(ca.issuer_alt_name, 'http://ian.ca.example.com')
        self.assertEqual(ca.crl_url, 'http://crl.example.com')
        self.assertEqual(ca.ocsp_url, 'http://ocsp.example.com')
        self.assertIssuer(ca, ca)
        self.assertAuthorityKeyIdentifier(ca, ca)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_no_pathlen(self):
        out, err = self.init_ca(pathlen=False)
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        ca = CertificateAuthority.objects.first()
        self.assertEqual(ca.pathlen, None)
        self.assertIssuer(ca, ca)
        self.assertAuthorityKeyIdentifier(ca, ca)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_empty_subject_fields(self):
        out, err = self.cmd('init_ca', 'test', '/C=/ST=/L=/O=/OU=/CN=test',
                            key_size=ca_settings.CA_MIN_KEY_SIZE)
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        ca = CertificateAuthority.objects.first()
        self.assertSubject(ca.x509c, {'CN': 'test'})
        self.assertIssuer(ca, ca)
        self.assertAuthorityKeyIdentifier(ca, ca)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_no_cn(self):
        out, err = self.cmd('init_ca', 'test', '/C=/ST=/L=/O=/OU=smth',
                            key_size=ca_settings.CA_MIN_KEY_SIZE)
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        ca = CertificateAuthority.objects.first()
        self.assertSubject(ca.x509c, {'OU': 'smth', 'CN': 'test'})
        self.assertIssuer(ca, ca)
        self.assertAuthorityKeyIdentifier(ca, ca)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_parent(self):
        self.init_ca(name='Parent')
        parent = CertificateAuthority.objects.get(name='Parent')

        # test that the default is not a child-relationship
        self.init_ca(name='Second')
        second = CertificateAuthority.objects.get(name='Second')
        self.assertIsNone(second.parent)

        self.init_ca(name='Child', parent=parent)
        child = CertificateAuthority.objects.get(name='Child')

        self.assertIsNone(parent.parent)
        self.assertEqual(child.parent, parent)
        self.assertEqual(list(child.children.all()), [])
        self.assertEqual(list(parent.children.all()), [child])
        self.assertIssuer(parent, child)
        self.assertAuthorityKeyIdentifier(parent, child)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_expires_override(self):
        # If we request an expiry after that of the parrent, we silently override to that of the
        # parent.

        self.init_ca(name='Parent')
        parent = CertificateAuthority.objects.get(name='Parent')

        # test that the default is not a child-relationship
        self.init_ca(name='Second')
        second = CertificateAuthority.objects.get(name='Second')
        self.assertIsNone(second.parent)

        self.init_ca(name='Child', parent=parent, expires=parent.expires + timedelta(days=10))
        child = CertificateAuthority.objects.get(name='Child')

        self.assertEqual(parent.expires, child.expires)
        self.assertIsNone(parent.parent)
        self.assertEqual(child.parent, parent)
        self.assertEqual(list(child.children.all()), [])
        self.assertEqual(list(parent.children.all()), [child])
        self.assertIssuer(parent, child)
        self.assertAuthorityKeyIdentifier(parent, child)

    @override_tmpcadir()
    def test_small_key_size(self):
        with self.assertRaises(CommandError):
            self.init_ca(key_size=256)

    @override_tmpcadir()
    def test_key_not_power_of_two(self):
        with self.assertRaises(CommandError):
            self.init_ca(key_size=2049)
