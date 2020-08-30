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
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from django.utils import timezone

from .. import ca_settings
from ..extensions import AuthorityInformationAccess
from ..extensions import CRLDistributionPoints
from ..extensions import NameConstraints
from ..models import CertificateAuthority
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
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca()
        self.assertTrue(pre.called)
        self.assertEqual(out, '')
        self.assertEqual(err, '')

        ca = CertificateAuthority.objects.first()
        self.assertPostCreateCa(post, ca)
        self.assertPrivateKey(ca)
        self.assertSerial(ca.serial)
        self.assertSignature([ca], ca)
        ca.full_clean()  # assert e.g. max_length in serials
        self.assertBasic(ca.x509, algo='sha512')

        # test the private key
        key = ca.key(None)
        self.assertIsInstance(key, RSAPrivateKey)
        self.assertEqual(key.key_size, 1024)

        self.assertSubject(ca.x509, [('C', 'AT'), ('ST', 'Vienna'), ('L', 'Vienna'),
                                     ('O', 'Org'), ('OU', 'OrgUnit'), ('CN', 'Test CA')])
        self.assertIssuer(ca, ca)
        self.assertAuthorityKeyIdentifier(ca, ca)
        self.assertEqual(ca.serial, int_to_hex(ca.x509.serial_number))

    @override_settings(USE_TZ=True)
    def test_basic_with_use_tz(self):
        return self.test_basic()

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_arguments(self):
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(
                algorithm=hashes.SHA1(),
                key_type='DSA',
                key_size=1024,
                expires=self.expires(720),
                pathlen=3,
                issuer_url='http://issuer.ca.example.com',
                issuer_alt_name={'value': ['http://ian.ca.example.com']},
                crl_url=['http://crl.example.com'],
                ocsp_url='http://ocsp.example.com',
                ca_issuer_url='http://ca.issuer.ca.example.com',
                permit_name=['DNS:.com'],
                exclude_name=['DNS:.net'],
            )
        self.assertTrue(pre.called)
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        ca = CertificateAuthority.objects.first()
        self.assertPostCreateCa(post, ca)
        self.assertPrivateKey(ca)
        self.assertSerial(ca.serial)
        ca.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([ca], ca)
        self.assertEqual(ca.name_constraints, NameConstraints({'value': {
            'permitted': ['DNS:.com'],
            'excluded': ['DNS:.net']
        }}))

        # test the private key
        key = ca.key(None)
        self.assertIsInstance(key, dsa.DSAPrivateKey)
        self.assertEqual(key.key_size, 1024)

        self.assertTrue(isinstance(ca.x509.signature_hash_algorithm, hashes.SHA1))
        self.assertTrue(isinstance(ca.x509.public_key(), dsa.DSAPublicKey))
        self.assertIsNone(ca.crl_distribution_points)
        self.assertEqual(ca.authority_information_access, AuthorityInformationAccess(
            {'value': {'issuers': ['URI:http://ca.issuer.ca.example.com']}}))
        self.assertEqual(ca.name_constraints, NameConstraints({'value': {
            'permitted': ['DNS:.com'],
            'excluded': ['DNS:.net']
        }}))
        self.assertEqual(ca.pathlen, 3)
        self.assertEqual(ca.max_pathlen, 3)
        self.assertTrue(ca.allows_intermediate_ca)
        self.assertEqual(ca.issuer_url, 'http://issuer.ca.example.com')
        self.assertEqual(ca.issuer_alt_name, 'URI:http://ian.ca.example.com')
        self.assertEqual(ca.crl_url, 'http://crl.example.com')
        self.assertEqual(ca.ocsp_url, 'http://ocsp.example.com')
        self.assertIssuer(ca, ca)
        self.assertAuthorityKeyIdentifier(ca, ca)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_ecc(self):
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(
                algorithm=hashes.SHA1(),
                key_type='ECC',
                key_size=1024,
                expires=self.expires(720),
                pathlen=3,
                issuer_url='http://issuer.ca.example.com',
                issuer_alt_name={'value': ['http://ian.ca.example.com']},
                crl_url=['http://crl.example.com'],
                ocsp_url='http://ocsp.example.com',
                ca_issuer_url='http://ca.issuer.ca.example.com',
                permit_name=['DNS:.com'],
                exclude_name=['DNS:.net'],
            )
        self.assertTrue(pre.called)
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        ca = CertificateAuthority.objects.first()
        self.assertPostCreateCa(post, ca)
        self.assertIsInstance(ca.key(None), ec.EllipticCurvePrivateKey)
        self.assertEqual(ca.name_constraints, NameConstraints({'value': {
            'permitted': ['DNS:.com'],
            'excluded': ['DNS:.net'],
        }}))

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_permitted(self):
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(
                name='permitted',
                permit_name=['DNS:.com'],
            )
        self.assertTrue(pre.called)
        self.assertEqual(out, '')
        self.assertEqual(err, '')

        ca = CertificateAuthority.objects.first()
        self.assertPostCreateCa(post, ca)
        self.assertSerial(ca.serial)
        ca.full_clean()  # assert e.g. max_length in serials
        self.assertPrivateKey(ca)
        self.assertSignature([ca], ca)
        self.assertEqual(ca.name_constraints, NameConstraints({'value': {'permitted': ['DNS:.com']}}))

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_excluded(self):
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(
                name='excluded',
                exclude_name=['DNS:.com'],
            )
        self.assertTrue(pre.called)
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        ca = CertificateAuthority.objects.first()
        self.assertPostCreateCa(post, ca)
        self.assertPrivateKey(ca)
        self.assertSerial(ca.serial)
        ca.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([ca], ca)
        self.assertEqual(ca.name_constraints, NameConstraints({'value': {'excluded': ['DNS:.com']}}))

    @override_settings(USE_TZ=True)
    def test_arguements_with_use_tz(self):
        self.test_arguments()

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_no_pathlen(self):
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(pathlen=None)
        self.assertTrue(pre.called)
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        ca = CertificateAuthority.objects.first()
        self.assertPostCreateCa(post, ca)
        self.assertSerial(ca.serial)
        ca.full_clean()  # assert e.g. max_length in serials
        self.assertPrivateKey(ca)
        self.assertSignature([ca], ca)
        self.assertEqual(ca.max_pathlen, None)
        self.assertEqual(ca.pathlen, None)
        self.assertTrue(ca.allows_intermediate_ca)
        self.assertIssuer(ca, ca)
        self.assertAuthorityKeyIdentifier(ca, ca)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_empty_subject_fields(self):
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.cmd('init_ca', 'test', '/C=/ST=/L=/O=/OU=/CN=test',
                                key_size=ca_settings.CA_MIN_KEY_SIZE)
        self.assertTrue(pre.called)
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        ca = CertificateAuthority.objects.first()
        self.assertPostCreateCa(post, ca)
        ca.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([ca], ca)
        self.assertSubject(ca.x509, [('CN', 'test')])
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
        self.assertPrivateKey(ca)
        self.assertSubject(ca.x509, [('OU', 'smth'), ('CN', 'test')])
        self.assertIssuer(ca, ca)
        self.assertAuthorityKeyIdentifier(ca, ca)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_parent(self):
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name='Parent', pathlen=1)
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        self.assertTrue(pre.called)
        parent = CertificateAuthority.objects.get(name='Parent')
        self.assertPostCreateCa(post, parent)
        parent.full_clean()  # assert e.g. max_length in serials
        self.assertPrivateKey(parent)
        self.assertSignature([parent], parent)

        # test that the default is not a child-relationship
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name='Second')
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        self.assertTrue(pre.called)

        second = CertificateAuthority.objects.get(name='Second')
        self.assertPostCreateCa(post, second)
        second.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([second], second)
        self.assertIsNone(second.parent)

        ca_crl_url = 'http://ca.crl.example.com'
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(
                name='Child', parent=parent,
                ca_crl_url=[ca_crl_url],
                ca_ocsp_url='http://ca.ocsp.example.com',
            )
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        self.assertTrue(pre.called)
        child = CertificateAuthority.objects.get(name='Child')
        self.assertPostCreateCa(post, child)
        child.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([parent], child)
        self.assertPrivateKey(child)

        self.assertIsNone(parent.parent)
        self.assertEqual(child.parent, parent)
        self.assertEqual(list(child.children.all()), [])
        self.assertEqual(list(parent.children.all()), [child])
        self.assertIssuer(parent, child)
        self.assertAuthorityKeyIdentifier(parent, child)
        self.assertEqual(child.crl_distribution_points, CRLDistributionPoints({
            'value': [{
                'full_name': [ca_crl_url],
            }]
        }))
        self.assertEqual(
            child.authority_information_access,
            AuthorityInformationAccess({'value': {
                'issuers': ['URI:http://%s/django_ca/issuer/%s.der' % (ca_settings.CA_DEFAULT_HOSTNAME,
                                                                       parent.serial)],
                'ocsp': ['URI:http://ca.ocsp.example.com'],
            }})
        )

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_intermediate_check(self):
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name='default')
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        self.assertTrue(pre.called)
        parent = CertificateAuthority.objects.get(name='default')
        self.assertPostCreateCa(post, parent)
        self.assertPrivateKey(parent)
        parent.full_clean()  # assert e.g. max_length in serials
        self.assertEqual(parent.pathlen, 0)
        self.assertEqual(parent.max_pathlen, 0)
        self.assertFalse(parent.allows_intermediate_ca)

        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name='pathlen-1', pathlen=1)
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        self.assertTrue(pre.called)
        pathlen_1 = CertificateAuthority.objects.get(name='pathlen-1')
        self.assertPostCreateCa(post, pathlen_1)
        pathlen_1.full_clean()  # assert e.g. max_length in serials
        self.assertPrivateKey(pathlen_1)
        self.assertEqual(pathlen_1.pathlen, 1)
        self.assertEqual(pathlen_1.max_pathlen, 1)
        self.assertTrue(pathlen_1.allows_intermediate_ca)

        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name='pathlen-1-none', pathlen=None, parent=pathlen_1)
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        self.assertTrue(pre.called)
        pathlen_1_none = CertificateAuthority.objects.get(name='pathlen-1-none')
        self.assertPostCreateCa(post, pathlen_1_none)
        pathlen_1_none.full_clean()  # assert e.g. max_length in serials
        self.assertPrivateKey(pathlen_1_none)

        # pathlen_1_none cannot have an intermediate CA because parent has pathlen=1
        self.assertIsNone(pathlen_1_none.pathlen)
        self.assertEqual(pathlen_1_none.max_pathlen, 0)
        self.assertFalse(pathlen_1_none.allows_intermediate_ca)
        with self.assertCommandError(
                r'^Parent CA cannot create intermediate CA due to pathlen restrictions\.$'), \
                self.assertCreateCASignals(False, False):
            out, err = self.init_ca(name='wrong', parent=pathlen_1_none)
        self.assertEqual(out, '')
        self.assertEqual(err, '')

        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name='pathlen-1-three', pathlen=3, parent=pathlen_1)
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        self.assertTrue(pre.called)
        pathlen_1_three = CertificateAuthority.objects.get(name='pathlen-1-three')
        self.assertPostCreateCa(post, pathlen_1_three)
        pathlen_1_three.full_clean()  # assert e.g. max_length in serials
        self.assertPrivateKey(pathlen_1_three)

        # pathlen_1_none cannot have an intermediate CA because parent has pathlen=1
        self.assertEqual(pathlen_1_three.pathlen, 3)
        self.assertEqual(pathlen_1_three.max_pathlen, 0)
        self.assertFalse(pathlen_1_three.allows_intermediate_ca)
        with self.assertCommandError(
                r'^Parent CA cannot create intermediate CA due to pathlen restrictions\.$'), \
                self.assertCreateCASignals(False, False):
            out, _err = self.init_ca(name='wrong', parent=pathlen_1_none)
        self.assertEqual(out, '')

        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name='pathlen-none', pathlen=None)
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        self.assertTrue(pre.called)
        pathlen_none = CertificateAuthority.objects.get(name='pathlen-none')
        self.assertPostCreateCa(post, pathlen_none)
        pathlen_none.full_clean()  # assert e.g. max_length in serials
        self.assertPrivateKey(pathlen_none)
        self.assertIsNone(pathlen_none.pathlen)
        self.assertIsNone(pathlen_none.max_pathlen, None)
        self.assertTrue(pathlen_none.allows_intermediate_ca)

        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name='pathlen-none-none', pathlen=None, parent=pathlen_none)
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        self.assertTrue(pre.called)
        pathlen_none_none = CertificateAuthority.objects.get(name='pathlen-none-none')
        self.assertPostCreateCa(post, pathlen_none_none)
        pathlen_none_none.full_clean()  # assert e.g. max_length in serials
        self.assertIsNone(pathlen_none_none.pathlen)
        self.assertIsNone(pathlen_none_none.max_pathlen)

        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name='pathlen-none-1', pathlen=1, parent=pathlen_none)
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        self.assertTrue(pre.called)
        pathlen_none_1 = CertificateAuthority.objects.get(name='pathlen-none-1')
        self.assertPostCreateCa(post, pathlen_none_1)
        pathlen_none_1.full_clean()  # assert e.g. max_length in serials
        self.assertEqual(pathlen_none_1.pathlen, 1)
        self.assertEqual(pathlen_none_1.max_pathlen, 1)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_expires_override(self):
        # If we request an expiry after that of the parrent, we silently override to that of the
        # parent.

        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name='Parent', pathlen=1)
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        self.assertTrue(pre.called)
        parent = CertificateAuthority.objects.get(name='Parent')
        self.assertPostCreateCa(post, parent)
        parent.full_clean()  # assert e.g. max_length in serials
        self.assertPrivateKey(parent)
        self.assertSignature([parent], parent)

        # test that the default is not a child-relationship
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name='Second')
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        self.assertTrue(pre.called)
        second = CertificateAuthority.objects.get(name='Second')
        self.assertPostCreateCa(post, second)
        second.full_clean()  # assert e.g. max_length in serials
        self.assertIsNone(second.parent)
        self.assertSignature([second], second)

        expires = parent.expires - timezone.now() + timedelta(days=10)
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name='Child', parent=parent, expires=expires)
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        self.assertTrue(pre.called)
        child = CertificateAuthority.objects.get(name='Child')
        self.assertPostCreateCa(post, child)
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
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name='Parent', password=password, pathlen=1)
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        self.assertTrue(pre.called)
        parent = CertificateAuthority.objects.get(name='Parent')
        self.assertPostCreateCa(post, parent)
        parent.full_clean()  # assert e.g. max_length in serials
        self.assertPrivateKey(parent, password=password)
        self.assertSignature([parent], parent)

        # Assert that we cannot access this without a password
        msg = '^Password was not given but private key is encrypted$'
        parent = CertificateAuthority.objects.get(name='Parent')
        with self.assertRaisesRegex(TypeError, msg):
            parent.key(None)

        # Wrong password doesn't work either
        with self.assertRaisesRegex(ValueError, self.re_false_password):
            parent.key(b'wrong')

        # test the private key
        key = parent.key(password)
        self.assertIsInstance(key, RSAPrivateKey)
        self.assertEqual(key.key_size, 1024)

        # create a child ca, also password protected
        child_password = b'childpassword'
        parent = CertificateAuthority.objects.get(name='Parent')  # Get again, key is cached

        with self.assertCommandError(r'^Password was not given but private key is encrypted$'), \
                self.assertCreateCASignals(False, False):
            out, err = self.init_ca(name='Child', parent=parent, password=child_password)
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        self.assertIsNone(CertificateAuthority.objects.filter(name='Child').first())

        # Create again with parent ca
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name='Child', parent=parent, password=child_password,
                                    parent_password=password)
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        self.assertTrue(pre.called)

        child = CertificateAuthority.objects.get(name='Child')
        self.assertPostCreateCa(post, child)
        child.full_clean()  # assert e.g. max_length in serials
        self.assertSignature([parent], child)

        # test the private key
        key = child.key(child_password)
        self.assertIsInstance(key, RSAPrivateKey)
        self.assertEqual(key.key_size, 1024)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_default_hostname(self):
        # test manually passing a default hostname
        self.load_usable_cas()

        name = 'ca'
        hostname = 'test-default-hostname.com'
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name=name, parent=self.cas['root'], default_hostname=hostname)
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        self.assertTrue(pre.called)
        ca = CertificateAuthority.objects.get(name=name)
        self.assertPostCreateCa(post, ca)

        self.assertEqual(ca.issuer_url,
                         'http://%s/django_ca/issuer/%s.der' % (hostname, self.cas['root'].serial))
        self.assertEqual(ca.ocsp_url,
                         'http://%s/django_ca/ocsp/%s/cert/' % (hostname, ca.serial))
        self.assertEqual(
            ca.authority_information_access,
            AuthorityInformationAccess({'value': {
                'issuers': ['URI:http://%s/django_ca/issuer/%s.der' % (hostname, ca.parent.serial)],
                'ocsp': ['URI:http://%s/django_ca/ocsp/%s/ca/' % (hostname, ca.parent.serial)],
            }})
        )

        ca_crl_url = 'http://%s%s' % (hostname, self.reverse('ca-crl', serial=self.cas['root'].serial))
        self.assertEqual(ca.crl_distribution_points, CRLDistributionPoints({
            'value': [{
                'full_name': [ca_crl_url],
            }]
        }))

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_no_default_hostname(self):
        # disable default hostname via the command line
        name = 'ca'
        with self.assertCreateCASignals() as (pre, post):
            out, err = self.init_ca(name=name, default_hostname=False)
        self.assertEqual(out, '')
        self.assertEqual(err, '')
        self.assertTrue(pre.called)
        ca = CertificateAuthority.objects.get(name=name)
        self.assertPostCreateCa(post, ca)

        self.assertIsNone(ca.issuer_url)
        self.assertIsNone(ca.ocsp_url)
        self.assertIsNone(ca.authority_information_access)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_root_ca_crl_url(self):
        with self.assertCommandError(r'^CRLs cannot be used to revoke root CAs\.$'), \
                self.assertCreateCASignals(False, False):
            self.init_ca(name='foobar', ca_crl_url='https://example.com')

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_root_ca_ocsp_url(self):
        with self.assertCommandError(r'^OCSP cannot be used to revoke root CAs\.$'), \
                self.assertCreateCASignals(False, False):
            self.init_ca(name='foobar', ca_ocsp_url='https://example.com')

    @override_tmpcadir()
    def test_small_key_size(self):
        with self.assertCommandError(r'^256: Key size must be least 1024 bits$'), \
                self.assertCreateCASignals(False, False):
            self.init_ca(key_size=256)

    @override_tmpcadir()
    def test_key_not_power_of_two(self):
        with self.assertCommandError(r'^2049: Key size must be a power of two$'), \
                self.assertCreateCASignals(False, False):
            self.init_ca(key_size=2049)
