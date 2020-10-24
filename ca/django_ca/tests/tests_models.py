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

"""Test Django model classes."""

import os
import re
from datetime import datetime
from datetime import timedelta
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.utils import IntegrityError
from django.test import TestCase
from django.utils import timezone

from freezegun import freeze_time

from .. import ca_settings
from ..constants import ReasonFlags
from ..extensions import KEY_TO_EXTENSION
from ..extensions import PrecertificateSignedCertificateTimestamps
from ..extensions import SubjectAlternativeName
from ..models import AcmeAccount
from ..models import Certificate
from ..models import Watcher
from ..subject import Subject
from ..utils import get_crl_cache_key
from .base import DjangoCAWithCertTestCase
from .base import DjangoCAWithGeneratedCAsTestCase
from .base import certs
from .base import override_settings
from .base import override_tmpcadir
from .base import timestamps


class TestWatcher(TestCase):
    """Test :py:class:`django_ca.models.Watcher`."""

    def test_from_addr(self):
        """Basic test for the ``from_addr()`` function."""
        mail = 'user@example.com'
        name = 'Firstname Lastname'

        watcher = Watcher.from_addr('%s <%s>' % (name, mail))
        self.assertEqual(watcher.mail, mail)
        self.assertEqual(watcher.name, name)

    def test_spaces(self):
        """Test that ``from_addr() is agnostic to spaces."""
        mail = 'user@example.com'
        name = 'Firstname Lastname'

        watcher = Watcher.from_addr('%s     <%s>' % (name, mail))
        self.assertEqual(watcher.mail, mail)
        self.assertEqual(watcher.name, name)

        watcher = Watcher.from_addr('%s<%s>' % (name, mail))
        self.assertEqual(watcher.mail, mail)
        self.assertEqual(watcher.name, name)

    def test_error(self):
        """Test some validation errors."""
        with self.assertRaises(ValidationError):
            Watcher.from_addr('foobar ')
        with self.assertRaises(ValidationError):
            Watcher.from_addr('foobar @')

    def test_update(self):
        """Test that from_addr updates the name if passed."""
        mail = 'user@example.com'
        name = 'Firstname Lastname'
        newname = 'Newfirst Newlast'

        Watcher.from_addr('%s <%s>' % (name, mail))
        watcher = Watcher.from_addr('%s <%s>' % (newname, mail))
        self.assertEqual(watcher.mail, mail)
        self.assertEqual(watcher.name, newname)

    def test_str(self):
        """Test the str function."""
        mail = 'user@example.com'
        name = 'Firstname Lastname'

        watcher = Watcher(mail=mail)
        self.assertEqual(str(watcher), mail)

        watcher.name = name
        self.assertEqual(str(watcher), '%s <%s>' % (name, mail))


class CertificateAuthorityTests(DjangoCAWithCertTestCase):
    @override_tmpcadir()
    def test_key(self):
        for name, ca in self.usable_cas.items():
            self.assertTrue(ca.key_exists)
            self.assertIsNotNone(ca.key(certs[name]['password']))

            # test a second tome to make sure we reload the key
            with mock.patch('django_ca.utils.read_file') as patched:
                self.assertIsNotNone(ca.key(None))
            patched.assert_not_called()

            ca._key = None  # so the key is reloaded
            ca.private_key_path = os.path.join(ca_settings.CA_DIR, ca.private_key_path)
            self.assertTrue(ca.key_exists)

            self.assertIsNotNone(ca.key(certs[name]['password']))

            # Check again - here we have an already loaded key (also: no logging here anymore)
            # NOTE: assertLogs() fails if there are *no* log messages, so we cannot test that
            self.assertTrue(ca.key_exists)

    def test_pathlen(self):
        for name, ca in self.cas.items():
            self.assertEqual(ca.pathlen, certs[name].get('pathlen'))

    def test_root(self):
        self.assertEqual(self.cas['root'].root, self.cas['root'])
        self.assertEqual(self.cas['child'].root, self.cas['root'])

    @freeze_time(timestamps['everything_valid'])
    @override_tmpcadir()
    def test_full_crl(self):
        ca = self.cas['root']
        child = self.cas['child']
        cert = self.certs['root-cert']
        full_name = 'http://localhost/crl'
        idp = self.get_idp(full_name=[x509.UniformResourceIdentifier(value=full_name)])

        crl = ca.get_crl(full_name=[full_name]).public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, signer=ca)

        ca.crl_url = full_name
        ca.save()
        crl = ca.get_crl().public_bytes(Encoding.PEM)
        self.assertCRL(crl, crl_number=1, signer=ca)

        # revoke a cert
        cert.revoke()
        crl = ca.get_crl().public_bytes(Encoding.PEM)
        self.assertCRL(crl, certs=[cert], crl_number=2, signer=ca)

        # also revoke a CA
        child.revoke()
        crl = ca.get_crl().public_bytes(Encoding.PEM)
        self.assertCRL(crl, certs=[cert, child], crl_number=3, signer=ca)

        # unrevoke cert (so we have all three combinations)
        cert.revoked = False
        cert.revoked_date = None
        cert.revoked_reason = ''
        cert.save()

        crl = ca.get_crl().public_bytes(Encoding.PEM)
        self.assertCRL(crl, certs=[child], crl_number=4, signer=ca)

    @freeze_time(timestamps['everything_valid'])
    @override_tmpcadir()
    def test_intermediate_crl(self):
        child = self.cas['child']
        cert = self.certs['child-cert']
        full_name = 'http://localhost/crl'
        idp = self.get_idp(full_name=[x509.UniformResourceIdentifier(value=full_name)])

        crl = child.get_crl(full_name=[full_name]).public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, signer=child)

        # Revoke a cert
        cert.revoke()
        crl = child.get_crl(full_name=[full_name]).public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, certs=[cert], crl_number=1, signer=child)

    @override_settings(USE_TZ=True)
    def test_full_crl_tz(self):
        # otherwise we get TZ warnings for preloaded objects
        ca = self.cas['root']
        child = self.cas['child']
        cert = self.certs['root-cert']

        ca.refresh_from_db()
        child.refresh_from_db()
        cert.refresh_from_db()

        self.test_full_crl()

    @override_tmpcadir()
    @freeze_time(timestamps['everything_valid'])
    def test_ca_crl(self):
        ca = self.cas['root']
        idp = self.get_idp(only_contains_ca_certs=True)   # root CAs don't have a full name (github issue #64)

        crl = ca.get_crl(scope='ca').public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, signer=ca)

        # revoke ca and cert, CRL only contains CA
        child_ca = self.cas['child']
        child_ca.revoke()
        self.cas['ecc'].revoke()
        self.certs['root-cert'].revoke()
        self.certs['child-cert'].revoke()
        crl = ca.get_crl(scope='ca').public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, certs=[child_ca], crl_number=1, signer=ca)

    @override_tmpcadir()
    @freeze_time(timestamps['everything_valid'])
    def test_intermediate_ca_crl(self):
        # Intermediate CAs have a DP in the CRL that has the CA url
        ca = self.cas['child']
        full_name = [x509.UniformResourceIdentifier(
            'http://%s/django_ca/crl/ca/%s/' % (ca_settings.CA_DEFAULT_HOSTNAME, ca.serial)
        )]
        idp = self.get_idp(full_name=full_name, only_contains_ca_certs=True)

        crl = ca.get_crl(scope='ca').public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, signer=ca)

    @freeze_time(timestamps['everything_valid'])
    @override_tmpcadir()
    def test_user_crl(self):
        ca = self.cas['root']
        idp = self.get_idp(full_name=self.get_idp_full_name(ca), only_contains_user_certs=True)

        crl = ca.get_crl(scope='user').public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, signer=ca)

        # revoke ca and cert, CRL only contains cert
        cert = self.certs['root-cert']
        cert.revoke()
        self.certs['child-cert'].revoke()
        self.cas['child'].revoke()
        crl = ca.get_crl(scope='user').public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, certs=[cert], crl_number=1, signer=ca)

    @freeze_time(timestamps['everything_valid'])
    @override_tmpcadir()
    def test_attr_crl(self):
        ca = self.cas['root']
        idp = self.get_idp(only_contains_attribute_certs=True)

        crl = ca.get_crl(scope='attribute').public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, signer=ca)

        # revoke ca and cert, CRL is empty (we don't know attribute certs)
        self.certs['root-cert'].revoke()
        self.certs['child-cert'].revoke()
        self.cas['child'].revoke()
        crl = ca.get_crl(scope='attribute').public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, crl_number=1, signer=ca)

    @override_tmpcadir()
    @freeze_time(timestamps['everything_valid'])
    def test_no_idp(self):
        # CRLs require a full name (or only_some_reasons) if it's a full CRL
        ca = self.cas['child']
        ca.crl_url = ''
        ca.save()
        crl = ca.get_crl().public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=None)

    @override_tmpcadir()
    @freeze_time(timestamps['everything_valid'])
    def test_counter(self):
        ca = self.cas['child']
        idp = self.get_idp(full_name=self.get_idp_full_name(ca))
        crl = ca.get_crl(counter='test').public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, crl_number=0)
        crl = ca.get_crl(counter='test').public_bytes(Encoding.PEM)
        self.assertCRL(crl, idp=idp, crl_number=1)

        crl = ca.get_crl().public_bytes(Encoding.PEM)  # test with no counter
        self.assertCRL(crl, idp=idp, crl_number=0)

    @override_tmpcadir()
    @freeze_time(timestamps['everything_valid'])
    def test_no_auth_key_identifier(self):
        # All CAs have a authority key identifier, so we mock that this exception is not present
        def side_effect(cls):
            raise x509.ExtensionNotFound('mocked', x509.SubjectKeyIdentifier.oid)

        ca = self.cas['child']
        full_name = 'http://localhost/crl'
        idp = self.get_idp(full_name=[x509.UniformResourceIdentifier(value=full_name)])

        with mock.patch('cryptography.x509.extensions.Extensions.get_extension_for_oid',
                        side_effect=side_effect):
            crl = ca.get_crl(full_name=[full_name]).public_bytes(Encoding.PEM)
        # Note that we still get an AKI because the value comes from the public key in this case
        self.assertCRL(crl, idp=idp, signer=ca)

    def test_validate_json(self):
        # Validation works if we're not revoked
        ca = self.cas['child']
        ca.full_clean()

        ca.crl_number = '{'
        # Note: we do not use self.assertValidationError, b/c the JSON message might be system dependent
        with self.assertRaises(ValidationError) as cm:
            ca.full_clean()
        self.assertTrue(re.match('Must be valid JSON: ', cm.exception.message_dict['crl_number'][0]))

    def test_crl_invalid_scope(self):
        ca = self.cas['child']
        with self.assertRaisesRegex(ValueError, r'^Scope must be either None, "ca", "user" or "attribute"$'):
            ca.get_crl(scope='foobar').public_bytes(Encoding.PEM)

    @override_tmpcadir()
    def test_cache_crls(self):
        crl_profiles = self.crl_profiles
        for config in crl_profiles.values():
            config['encodings'] = ['DER', 'PEM', ]

        for name, ca in self.usable_cas.items():
            der_user_key = get_crl_cache_key(ca.serial, hashes.SHA512, Encoding.DER, 'user')
            pem_user_key = get_crl_cache_key(ca.serial, hashes.SHA512, Encoding.PEM, 'user')
            der_ca_key = get_crl_cache_key(ca.serial, hashes.SHA512, Encoding.DER, 'ca')
            pem_ca_key = get_crl_cache_key(ca.serial, hashes.SHA512, Encoding.PEM, 'ca')

            self.assertIsNone(cache.get(der_ca_key))
            self.assertIsNone(cache.get(pem_ca_key))
            self.assertIsNone(cache.get(der_user_key))
            self.assertIsNone(cache.get(pem_user_key))

            with self.settings(CA_CRL_PROFILES=crl_profiles):
                ca.cache_crls()

            der_user_crl = cache.get(der_user_key)
            pem_user_crl = cache.get(pem_user_key)
            self.assertIsInstance(der_user_crl, bytes)
            self.assertIsInstance(pem_user_crl, bytes)

            der_ca_crl = cache.get(der_ca_key)
            pem_ca_crl = cache.get(pem_ca_key)
            self.assertIsInstance(der_ca_crl, bytes)
            self.assertIsInstance(pem_ca_crl, bytes)

            # cache again - which should not trigger a new computation
            with self.settings(CA_CRL_PROFILES=crl_profiles):
                ca.cache_crls()

            new_der_user_crl = cache.get(der_user_key)
            new_pem_user_crl = cache.get(pem_user_key)
            self.assertIsInstance(der_user_crl, bytes)
            self.assertIsInstance(pem_user_crl, bytes)
            self.assertEqual(new_der_user_crl, der_user_crl)
            self.assertEqual(new_pem_user_crl, pem_user_crl)

            new_der_ca_crl = cache.get(der_ca_key)
            new_pem_ca_crl = cache.get(pem_ca_key)
            self.assertEqual(new_der_ca_crl, der_ca_crl)
            self.assertEqual(new_pem_ca_crl, pem_ca_crl)

            # clear caches and skip generation
            cache.clear()
            crl_profiles['ca']['OVERRIDES'][ca.serial]['skip'] = True
            crl_profiles['user']['OVERRIDES'][ca.serial]['skip'] = True

            # set a wrong password, ensuring that any CRL generation would *never* work
            crl_profiles['ca']['OVERRIDES'][ca.serial]['password'] = b'wrong'
            crl_profiles['user']['OVERRIDES'][ca.serial]['password'] = b'wrong'

            with self.settings(CA_CRL_PROFILES=crl_profiles):
                ca.cache_crls()

            self.assertIsNone(cache.get(der_ca_key))
            self.assertIsNone(cache.get(pem_ca_key))
            self.assertIsNone(cache.get(der_user_key))
            self.assertIsNone(cache.get(pem_user_key))


class CertificateTests(DjangoCAWithCertTestCase):
    def assertExtension(self, cert, name, key, cls):
        ext = getattr(cert, key)

        if ext is None:
            self.assertNotIn(key, certs[name])
        else:
            self.assertIsInstance(ext, cls)
            self.assertEqual(ext, certs[name].get(key))

    def test_dates(self):
        for name, ca in self.cas.items():
            self.assertEqual(ca.valid_from, certs[name]['valid_from'])
            self.assertEqual(ca.expires, certs[name]['valid_until'])

        for name, cert in self.certs.items():
            self.assertEqual(cert.valid_from, certs[name]['valid_from'])
            self.assertEqual(cert.expires, certs[name]['valid_until'])

    def test_max_pathlen(self):
        for name, ca in self.usable_cas.items():
            expected = certs[name].get('max_pathlen')
            self.assertEqual(ca.max_pathlen, expected)

    def test_allows_intermediate(self):
        self.assertTrue(self.cas['root'].allows_intermediate_ca)
        self.assertTrue(self.cas['ecc'].allows_intermediate_ca)
        self.assertFalse(self.cas['child'].allows_intermediate_ca)

    def test_revocation(self):
        # Never really happens in real life, but should still be checked
        c = Certificate(revoked=False)

        with self.assertRaises(ValueError):
            c.get_revocation()

    def test_root(self):
        self.assertEqual(self.certs['root-cert'].root, self.cas['root'])
        self.assertEqual(self.certs['child-cert'].root, self.cas['root'])

    @override_tmpcadir()
    def test_serial(self):
        for name, ca in self.cas.items():
            self.assertEqual(ca.serial, certs[ca.name].get('serial'))

        for name, cert in self.certs.items():
            self.assertEqual(cert.serial, certs[name].get('serial'))

    @override_tmpcadir()
    def test_subject_alternative_name(self):
        for name, ca in self.cas.items():
            self.assertEqual(ca.subject_alternative_name, certs[ca.name].get('subject_alternative_name'))

        for name, cert in self.certs.items():
            self.assertEqual(cert.subject_alternative_name, certs[name].get('subject_alternative_name'))

        # Create a cert with some weirder SANs to test that too
        full = self.create_cert(
            self.cas['child'], certs['child-cert']['csr']['pem'], subject=Subject({'CN': 'all.example.com'}),
            extensions=[SubjectAlternativeName({
                'value': ['dirname:/C=AT/CN=example.com', 'email:user@example.com', 'fd00::1'],
            })]
        )

        expected = SubjectAlternativeName({'value': [
            'dirname:/C=AT/CN=example.com', 'email:user@example.com', 'IP:fd00::1', 'DNS:all.example.com',
        ]})
        self.assertEqual(full.subject_alternative_name, expected)

    @freeze_time("2019-02-03 15:43:12")
    def test_get_revocation_time(self):
        cert = self.certs['child-cert']
        self.assertIsNone(cert.get_revocation_time())
        cert.revoke()

        with override_settings(USE_TZ=True):
            cert.revoked_date = timezone.now()
            self.assertEqual(cert.get_revocation_time(), datetime(2019, 2, 3, 15, 43, 12))

        with override_settings(USE_TZ=False):
            cert.revoked_date = timezone.now()
            self.assertEqual(cert.get_revocation_time(), datetime(2019, 2, 3, 15, 43, 12))

    @freeze_time("2019-02-03 15:43:12")
    def test_get_compromised_time(self):
        cert = self.certs['child-cert']
        self.assertIsNone(cert.get_compromised_time())
        cert.revoke(compromised=timezone.now())

        with override_settings(USE_TZ=True):
            cert.compromised = timezone.now()
            self.assertEqual(cert.get_compromised_time(), datetime(2019, 2, 3, 15, 43, 12))

        with override_settings(USE_TZ=False):
            cert.compromised = timezone.now()
            self.assertEqual(cert.get_compromised_time(), datetime(2019, 2, 3, 15, 43, 12))

    def test_get_revocation_reason(self):
        cert = self.certs['child-cert']
        self.assertIsNone(cert.get_revocation_reason())

        for reason in ReasonFlags:
            cert.revoke(reason)
            got = cert.get_revocation_reason()
            self.assertIsInstance(got, x509.ReasonFlags)
            self.assertEqual(got.name, reason.name)

    def test_validate_past(self):
        # Test that model validation does not allow us to set revoked_date or revoked_invalidity to the future
        cert = self.certs['child-cert']
        now = timezone.now()
        future = now + timedelta(10)
        past = now - timedelta(10)

        # Validation works if we're not revoked
        cert.full_clean()

        # Validation works if date is in the past
        cert.revoked_date = past
        cert.compromised = past
        cert.full_clean()

        cert.revoked_date = future
        cert.compromised = future
        with self.assertValidationError({
                'compromised': ['Date must be in the past!'],
                'revoked_date': ['Date must be in the past!'],
        }):
            cert.full_clean()

    def test_digest(self):
        for name, ca in self.cas.items():
            self.assertEqual(ca.get_digest('md5'), certs[name]['md5'])
            self.assertEqual(ca.get_digest('sha1'), certs[name]['sha1'])
            self.assertEqual(ca.get_digest('sha256'), certs[name]['sha256'])
            self.assertEqual(ca.get_digest('sha512'), certs[name]['sha512'])

        for name, cert in self.certs.items():
            self.assertEqual(cert.get_digest('md5'), certs[name]['md5'])
            self.assertEqual(cert.get_digest('sha1'), certs[name]['sha1'])
            self.assertEqual(cert.get_digest('sha256'), certs[name]['sha256'])
            self.assertEqual(cert.get_digest('sha512'), certs[name]['sha512'])

    def test_hpkp_pin(self):
        # get hpkp pins using
        #   openssl x509 -in cert1.pem -pubkey -noout \
        #       | openssl rsa -pubin -outform der \
        #       | openssl dgst -sha256 -binary | base64
        for name, ca in self.cas.items():
            self.assertEqual(ca.hpkp_pin, certs[name]['hpkp'])
            self.assertIsInstance(ca.hpkp_pin, str)

        for name, cert in self.certs.items():
            self.assertEqual(cert.hpkp_pin, certs[name]['hpkp'])
            self.assertIsInstance(cert.hpkp_pin, str)

    def test_get_authority_key_identifier(self):
        for name, ca in self.cas.items():
            self.assertEqual(ca.get_authority_key_identifier().key_identifier,
                             certs[name]['subject_key_identifier'].value)

        # All CAs have a subject key identifier, so we mock that this exception is not present
        def side_effect(cls):
            raise x509.ExtensionNotFound('mocked', x509.SubjectKeyIdentifier.oid)

        ca = self.cas['child']
        with mock.patch('cryptography.x509.extensions.Extensions.get_extension_for_class',
                        side_effect=side_effect):
            self.assertEqual(ca.get_authority_key_identifier().key_identifier,
                             certs['child']['subject_key_identifier'].value)

    def test_get_authority_key_identifier_extension(self):
        for name, ca in self.cas.items():
            self.assertEqual(ca.get_authority_key_identifier_extension().key_identifier,
                             certs[name]['subject_key_identifier'].value)

    ###############################################
    # Test extensions for all loaded certificates #
    ###############################################
    def test_extensions(self):
        for key, cls in KEY_TO_EXTENSION.items():
            if key == PrecertificateSignedCertificateTimestamps.key:
                # These extensions are never equal:
                # Since we cannot instantiate this extension, the value is stored internally as cryptography
                # object if it comes from the extension (or there would be no way back), but as serialized
                # data if instantiated from dict (b/c we cannot create the cryptography objects).
                continue

            for name, ca in self.cas.items():
                self.assertExtension(ca, name, key, cls)

            for name, cert in self.certs.items():
                self.assertExtension(cert, name, key, cls)

    #@unittest.skip('Cannot currently instantiate extensions, so no sense in testing this.')
    def test_precertificate_signed_certificate_timestamps(self):
        for name, cert in self.certs.items():
            ext = getattr(cert, PrecertificateSignedCertificateTimestamps.key)

            if PrecertificateSignedCertificateTimestamps.key in certs[name]:
                self.assertIsInstance(ext, PrecertificateSignedCertificateTimestamps)
            else:
                self.assertIsNone(ext)


class AcmeAccountTestCase(DjangoCAWithGeneratedCAsTestCase):
    """Test :py:class:`django_ca.models.AcmeAccount`."""

    thumbprint1 = 'U-yUM27CQn9pClKlEITobHB38GJOJ9YbOxnw5KKqU-8'
    thumbprint2 = 's_glgc6Fem0CW7ZioXHBeuUQVHSO-viZ3xNR8TBebCo'
    pem1 = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvP5N/1KjBQniyyukn30E
tyHz6cIYPv5u5zZbHGfNvrmMl8qHMmddQSv581AAFa21zueS+W8jnRI5ISxER95J
tNad2XEDsFINNvYaSG8E54IHMNQijVLR4MJchkfMAa6g1gIsJB+ffEt4Ea3TMyGr
MifJG0EjmtjkjKFbr2zuPhRX3fIGjZTlkxgvb1AY2P4AxALwS/hG4bsxHHNxHt2Z
s9Bekv+55T5+ZqvhNz1/3yADRapEn6dxHRoUhnYebqNLSVoEefM+h5k7AS48waJS
lKC17RMZfUgGE/5iMNeg9qtmgWgZOIgWDyPEpiXZEDDKeoifzwn1LO59W8c4W6L7
XwIDAQAB
-----END PUBLIC KEY-----'''
    pem2 = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp8SCUVQqpTBRyryuu560
Q8cAi18Ac+iLjaSLL4gOaDEU9CpPi4l9yCGphnQFQ92YP+GWv+C6/JRp24852QbR
RzuUJqJPdDxD78yFXoxYCLPmwQMnToA7SE3SnZ/PW2GPFMbAICuRdd3PhMAWCODS
NewZPLBlG35brRlfFtUEc2oQARb2lhBkMXrpIWeuSNQtInAHtfTJNA51BzdrIT2t
MIfadw4ljk7cVbrSYemT6e59ATYxiMXalu5/4v22958voEBZ38TE8AXWiEtTQYwv
/Kj0P67yuzE94zNdT28pu+jJYr5nHusa2NCbvnYFkDwzigmwCxVt9kW3xj3gfpgc
VQIDAQAB
-----END PUBLIC KEY-----'''

    def setUp(self):
        super().setUp()
        self.account1 = AcmeAccount.objects.create(ca=self.cas['root'], contact='user@example.com',
                                                   terms_of_service_agreed=True,
                                                   status=AcmeAccount.STATUS_VALID, pem=self.pem1,
                                                   thumbprint=self.thumbprint1)
        self.account2 = AcmeAccount.objects.create(ca=self.cas['child'], contact='user@example.net',
                                                   terms_of_service_agreed=False,
                                                   status=AcmeAccount.STATUS_REVOKED, pem=self.pem2,
                                                   thumbprint=self.thumbprint2)

    def test_str(self):
        """Test str() function."""
        self.assertEqual(str(self.account1), self.account1.contact)
        self.assertEqual(str(self.account2), self.account2.contact)
        self.assertEqual(str(AcmeAccount()), '')

    def test_serial(self):
        """Test the ``serial`` property."""
        self.assertEqual(self.account1.serial, self.cas['root'].serial)
        self.assertEqual(self.account2.serial, self.cas['child'].serial)

        # pylint: disable=no-member; false positive: pylint does not detect RelatedObjectDoesNotExist member
        with self.assertRaisesRegex(AcmeAccount.ca.RelatedObjectDoesNotExist, r'^AcmeAccount has no ca\.$'):
            AcmeAccount().serial  # pylint: disable=expression-not-assigned

    def test_usable(self):
        """Test the ``usable`` property."""
        self.assertTrue(self.account1.usable)
        self.assertFalse(self.account2.usable)

        # Try states that make an account **unusable**
        self.account1.status = AcmeAccount.STATUS_DEACTIVATED
        self.assertFalse(self.account1.usable)
        self.account1.status = AcmeAccount.STATUS_REVOKED
        self.assertFalse(self.account1.usable)

        # Make the account usable again
        self.account1.status = AcmeAccount.STATUS_VALID
        self.assertTrue(self.account1.usable)

        # TOS must be agreed
        self.account1.terms_of_service_agreed = False
        self.assertFalse(self.account1.usable)

        # Make the account usable again
        self.account1.terms_of_service_agreed = True
        self.assertTrue(self.account1.usable)

        # If the CA is not usable, neither is the account
        self.account1.ca.enabled = False
        self.assertFalse(self.account1.usable)

    def test_unique_together(self):
        """Test that a thumbprint must be unique for the given CA."""

        msg = r'^UNIQUE constraint failed: django_ca_acmeaccount\.ca_id, django_ca_acmeaccount\.thumbprint$'
        with transaction.atomic(), self.assertRaisesRegex(IntegrityError, msg):
            AcmeAccount.objects.create(ca=self.account1.ca, thumbprint=self.account1.thumbprint)

        # Works, because CA is different
        AcmeAccount.objects.create(ca=self.account2.ca, thumbprint=self.account1.thumbprint)
