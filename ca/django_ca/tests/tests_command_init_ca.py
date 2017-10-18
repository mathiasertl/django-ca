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
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from django.core.management.base import CommandError

from django_ca.models import CertificateAuthority

from .. import ca_settings
from ..utils import int_to_hex
from .base import DjangoCATestCase
from .base import override_settings
from .base import override_tmpcadir


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
        self.assertSignature([ca], ca)
        ca.full_clean()  # assert e.g. max_length in serials
        self.assertBasic(ca.x509, algo='sha512')

        # test the private key
        key = ca.key(None)
        self.assertIsInstance(key, RSAPrivateKey)
        self.assertEqual(key.key_size, 1024)

        self.assertSubject(ca.x509, {'C': 'AT', 'ST': 'Vienna', 'L': 'Vienna', 'O': 'Org',
                                     'OU': 'OrgUnit', 'CN': 'Test CA'})
        self.assertIssuer(ca, ca)
        self.assertAuthorityKeyIdentifier(ca, ca)
        self.assertEqual(ca.serial, int_to_hex(ca.x509.serial_number))

    @override_settings(USE_TZ=True)
    def test_basic_with_use_tz(self):
        return self.test_basic()

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
            name_constraint=['permitted;DNS:.com', 'excluded;DNS:.net'],
        )
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        ca = CertificateAuthority.objects.first()
        ca.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([ca], ca)

        # test the private key
        key = ca.key(None)
        self.assertIsInstance(key, dsa.DSAPrivateKey)
        self.assertEqual(key.key_size, 1024)

        self.assertTrue(isinstance(ca.x509.signature_hash_algorithm, hashes.SHA1))
        self.assertTrue(isinstance(ca.x509.public_key(), dsa.DSAPublicKey))
        self.assertEqual(ca.crlDistributionPoints(), 'Full Name: URI:http://ca.crl.example.com')
        self.assertEqual(ca.authorityInfoAccess(),
                         'OCSP - URI:http://ca.ocsp.example.com\n'
                         'CA Issuers - URI:http://ca.issuer.ca.example.com\n')
        self.assertEqual(ca.nameConstraints(),
                         'critical,Permitted:\n  DNS:.com\nExcluded:\n  DNS:.net\n')
        self.assertEqual(ca.pathlen, 3)
        self.assertEqual(ca.issuer_url, 'http://issuer.ca.example.com')
        self.assertEqual(ca.issuer_alt_name, 'http://ian.ca.example.com')
        self.assertEqual(ca.crl_url, 'http://crl.example.com')
        self.assertEqual(ca.ocsp_url, 'http://ocsp.example.com')
        self.assertIssuer(ca, ca)
        self.assertAuthorityKeyIdentifier(ca, ca)

    @override_settings(USE_TZ=True)
    def test_arguements_with_use_tz(self):
        self.test_arguments()

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_no_pathlen(self):
        out, err = self.init_ca(pathlen=None)
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        ca = CertificateAuthority.objects.first()
        ca.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([ca], ca)
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
        ca.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([ca], ca)
        self.assertSubject(ca.x509, {'CN': 'test'})
        self.assertIssuer(ca, ca)
        self.assertAuthorityKeyIdentifier(ca, ca)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_no_cn(self):
        out, err = self.cmd('init_ca', 'test', '/C=/ST=/L=/O=/OU=smth',
                            key_size=ca_settings.CA_MIN_KEY_SIZE)
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        ca = CertificateAuthority.objects.first()
        ca.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([ca], ca)
        self.assertSubject(ca.x509, {'OU': 'smth', 'CN': 'test'})
        self.assertIssuer(ca, ca)
        self.assertAuthorityKeyIdentifier(ca, ca)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_parent(self):
        self.init_ca(name='Parent')
        parent = CertificateAuthority.objects.get(name='Parent')
        parent.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([parent], parent)

        # test that the default is not a child-relationship
        self.init_ca(name='Second')
        second = CertificateAuthority.objects.get(name='Second')
        second.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([second], second)
        self.assertIsNone(second.parent)

        self.init_ca(name='Child', parent=parent)
        child = CertificateAuthority.objects.get(name='Child')
        child.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([parent], child)

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
        parent.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([parent], parent)

        # test that the default is not a child-relationship
        self.init_ca(name='Second')
        second = CertificateAuthority.objects.get(name='Second')
        second.full_clean()  # assert e.g. max_length in serials
        self.assertIsNone(second.parent)
        self.assertSignature([second], second)

        self.init_ca(name='Child', parent=parent, expires=parent.expires + timedelta(days=10))
        child = CertificateAuthority.objects.get(name='Child')
        child.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([parent], child)

        self.assertEqual(parent.expires, child.expires)
        self.assertIsNone(parent.parent)
        self.assertEqual(child.parent, parent)
        self.assertEqual(list(child.children.all()), [])
        self.assertEqual(list(parent.children.all()), [child])
        self.assertIssuer(parent, child)
        self.assertAuthorityKeyIdentifier(parent, child)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_password(self):
        password = b'testpassword'
        self.init_ca(name='Parent', password=password)
        parent = CertificateAuthority.objects.get(name='Parent')
        parent.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([parent], parent)

        # Assert that we cannot access this without a password
        msg = '^Password was not given but private key is encrypted$'
        with self.assertRaisesRegex(TypeError, msg):
            parent.key(None)

        # Wrong password doesn't work either
        with self.assertRaisesRegex(ValueError, '^Bad decrypt. Incorrect password?'):
            parent.key(b'wrong')

        # test the private key
        key = parent.key(password)
        self.assertIsInstance(key, RSAPrivateKey)
        self.assertEqual(key.key_size, 1024)

        # create a child ca, also password protected
        child_password = b'childpassword'
        parent = CertificateAuthority.objects.get(name='Parent')  # Get again, key is cached

        with self.assertRaisesRegex(CommandError, '^Password was not given but private key is encrypted$'):
            self.init_ca(name='Child', parent=parent, password=child_password)
        self.assertIsNone(CertificateAuthority.objects.filter(name='Child').first())

        # Create again with parent ca
        self.init_ca(name='Child', parent=parent, password=child_password, parent_password=password)

        child = CertificateAuthority.objects.get(name='Child')
        child.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([parent], child)

        # test the private key
        key = child.key(child_password)
        self.assertIsInstance(key, RSAPrivateKey)
        self.assertEqual(key.key_size, 1024)

    # Test that a false CA_DIGEST_ALGORITHM raises a CommandError
    @override_tmpcadir(CA_DIGEST_ALGORITHM='broken')
    def test_wrong_algorithm(self):
        with self.assertRaisesRegex(CommandError, '^Error: Unknown hash algorithm: broken$'):
            self.init_ca(name='foobar')

    @override_tmpcadir()
    def test_small_key_size(self):
        with self.assertRaises(CommandError):
            self.init_ca(key_size=256)

    @override_tmpcadir()
    def test_key_not_power_of_two(self):
        with self.assertRaises(CommandError):
            self.init_ca(key_size=2049)
