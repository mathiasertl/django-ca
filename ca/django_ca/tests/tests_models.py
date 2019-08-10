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

import os
import re
import unittest
from datetime import datetime
from datetime import timedelta

import six
from freezegun import freeze_time

from cryptography import x509

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

from .. import ca_settings
from ..constants import ReasonFlags
from ..extensions import AuthorityInformationAccess
from ..extensions import AuthorityKeyIdentifier
from ..extensions import BasicConstraints
from ..extensions import ExtendedKeyUsage
from ..extensions import IssuerAlternativeName
from ..extensions import KeyUsage
from ..extensions import NameConstraints
from ..extensions import OCSPNoCheck
from ..extensions import PrecertPoison
from ..extensions import PrecertificateSignedCertificateTimestamps
from ..extensions import SubjectAlternativeName
from ..extensions import SubjectKeyIdentifier
from ..extensions import TLSFeature
from ..models import Certificate
from ..models import Watcher
from .base import DjangoCAWithCertTestCase
from .base import certs
from .base import override_settings
from .base import override_tmpcadir
from .base import timestamps

try:
    import unittest.mock as mock
except ImportError:
    import mock


class TestWatcher(TestCase):
    def test_from_addr(self):
        mail = 'user@example.com'
        name = 'Firstname Lastname'

        w = Watcher.from_addr('%s <%s>' % (name, mail))
        self.assertEqual(w.mail, mail)
        self.assertEqual(w.name, name)

    def test_spaces(self):
        mail = 'user@example.com'
        name = 'Firstname Lastname'

        w = Watcher.from_addr('%s     <%s>' % (name, mail))
        self.assertEqual(w.mail, mail)
        self.assertEqual(w.name, name)

        w = Watcher.from_addr('%s<%s>' % (name, mail))
        self.assertEqual(w.mail, mail)
        self.assertEqual(w.name, name)

    def test_error(self):
        with self.assertRaises(ValidationError):
            Watcher.from_addr('foobar ')
        with self.assertRaises(ValidationError):
            Watcher.from_addr('foobar @')

    def test_update(self):
        mail = 'user@example.com'
        name = 'Firstname Lastname'
        newname = 'Newfirst Newlast'

        Watcher.from_addr('%s <%s>' % (name, mail))
        w = Watcher.from_addr('%s <%s>' % (newname, mail))
        self.assertEqual(w.mail, mail)
        self.assertEqual(w.name, newname)

    def test_output(self):
        mail = 'user@example.com'
        name = 'Firstname Lastname'

        w = Watcher(mail=mail)
        self.assertEqual(str(w), mail)

        w.name = name
        self.assertEqual(str(w), '%s <%s>' % (name, mail))


class CertificateAuthorityTests(DjangoCAWithCertTestCase):
    @override_tmpcadir()
    def test_key(self):
        log_msg = 'WARNING:django_ca.models:%s: CA uses absolute path. Use "manage.py migrate_ca" to update.'

        for name, ca in self.usable_cas.items():
            self.assertTrue(ca.key_exists)
            self.assertIsNotNone(ca.key(certs[name]['password']))

            # test a second tome to make sure we reload the key
            with mock.patch('django_ca.utils.read_file') as patched:
                self.assertIsNotNone(ca.key(None))
            patched.assert_not_called()

            ca._key = None  # so the key is reloaded
            ca.private_key_path = os.path.join(ca_settings.CA_DIR, ca.private_key_path)

            with self.assertLogs() as cm:
                self.assertTrue(ca.key_exists)
            self.assertEqual(cm.output, [log_msg % ca.serial, ])

            with self.assertLogs() as cm:
                self.assertIsNotNone(ca.key(certs[name]['password']))
            self.assertEqual(cm.output, [log_msg % ca.serial, ])

            # Check again - here we have an already loaded key (also: no logging here anymore)
            # NOTE: assertLogs() fails if there are *no* log messages, so we cannot test that
            self.assertTrue(ca.key_exists)

    def test_pathlen(self):
        for name, ca in self.cas.items():
            self.assertEqual(ca.pathlen, certs[name].get('pathlen'))

    def test_root(self):
        self.assertEqual(self.cas['root'].root, self.cas['root'])
        self.assertEqual(self.cas['child'].root, self.cas['root'])

    @freeze_time('2019-04-14 12:26:00')
    @override_tmpcadir()
    def test_full_crl(self):
        ca = self.cas['root']
        child = self.cas['child']
        cert = self.certs['root-cert']
        full_name = 'http://localhost/crl'
        idp = self.get_idp(full_name=[x509.UniformResourceIdentifier(value=full_name)])

        self.assertIsNone(ca.crl_url)
        crl = ca.get_crl(full_name=[full_name])
        self.assertCRL(crl, idp=idp, signer=ca)

        ca.crl_url = full_name
        ca.save()
        crl = ca.get_crl()
        self.assertCRL(crl, idp=idp, crl_number=1, signer=ca)

        # revoke a cert
        cert.revoke()
        crl = ca.get_crl()
        self.assertCRL(crl, idp=idp, certs=[cert], crl_number=2, signer=ca)

        # also revoke a CA
        child.revoke()
        crl = ca.get_crl()
        self.assertCRL(crl, idp=idp, certs=[cert, child], crl_number=3, signer=ca)

        # unrevoke cert (so we have all three combinations)
        cert.revoked = False
        cert.revoked_date = None
        cert.revoked_reason = None
        cert.save()

        crl = ca.get_crl()
        self.assertCRL(crl, idp=idp, certs=[child], crl_number=4, signer=ca)

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
    @freeze_time('2019-04-14 12:26:00')
    def test_ca_crl(self):
        ca = self.cas['root']
        idp = self.get_idp(only_contains_ca_certs=True)

        self.assertIsNone(ca.crl_url)
        crl = ca.get_crl(scope='ca')
        self.assertCRL(crl, idp=idp, signer=ca)

        # revoke ca and cert, CRL only contains CA
        child_ca = self.cas['child']
        child_ca.revoke()
        self.cas['ecc'].revoke()
        self.certs['root-cert'].revoke()
        self.certs['child-cert'].revoke()
        crl = ca.get_crl(scope='ca')
        self.assertCRL(crl, idp=idp, certs=[child_ca], crl_number=1, signer=ca)

    @freeze_time('2019-04-14 12:26:00')
    @override_tmpcadir()
    def test_user_crl(self):
        ca = self.cas['root']
        idp = self.get_idp(only_contains_user_certs=True)

        self.assertIsNone(ca.crl_url)
        crl = ca.get_crl(scope='user')
        self.assertCRL(crl, idp=idp, signer=ca)

        # revoke ca and cert, CRL only contains cert
        cert = self.certs['root-cert']
        cert.revoke()
        self.certs['child-cert'].revoke()
        self.cas['child'].revoke()
        crl = ca.get_crl(scope='user')
        self.assertCRL(crl, idp=idp, certs=[cert], crl_number=1, signer=ca)

    @freeze_time('2019-04-14 12:26:00')
    @override_tmpcadir()
    def test_attr_crl(self):
        ca = self.cas['root']
        idp = self.get_idp(only_contains_attribute_certs=True)

        self.assertIsNone(ca.crl_url)
        crl = ca.get_crl(scope='attribute')
        self.assertCRL(crl, idp=idp, signer=ca)

        # revoke ca and cert, CRL is empty (we don't know attribute certs)
        self.certs['root-cert'].revoke()
        self.certs['child-cert'].revoke()
        self.cas['child'].revoke()
        crl = ca.get_crl(scope='attribute')
        self.assertCRL(crl, idp=idp, crl_number=1, signer=ca)

    @override_tmpcadir()
    @freeze_time('2019-04-14 12:26:00')
    @unittest.skipUnless(ca_settings.CRYPTOGRAPHY_HAS_IDP, "Test requires cryptography>=2.5")
    def test_no_idp(self):
        # CRLs require a full name (or only_some_reasons) if it's a full CRL
        ca = self.cas['child']
        self.assertIsNone(ca.crl_url)
        crl = ca.get_crl()
        self.assertCRL(crl, idp=None)

    @override_tmpcadir()
    @freeze_time('2019-04-14 12:26:00')
    def test_counter(self):
        ca = self.cas['child']
        crl = ca.get_crl(counter='test')
        self.assertCRL(crl, idp=None, crl_number=0)
        crl = ca.get_crl(counter='test')
        self.assertCRL(crl, idp=None, crl_number=1)

        crl = ca.get_crl()
        self.assertCRL(crl, idp=None, crl_number=0)

    @override_tmpcadir()
    @freeze_time(timestamps['everything_valid'])
    def test_no_auth_key_identifier(self):
        # All CAs have a authority key identifier, so we mock that this exception is not present
        def side_effect(cls):
            raise x509.ExtensionNotFound('mocked', x509.AuthorityKeyIdentifier.oid)

        ca = self.cas['child']
        full_name = 'http://localhost/crl'
        idp = self.get_idp(full_name=[x509.UniformResourceIdentifier(value=full_name)])

        with mock.patch('cryptography.x509.extensions.Extensions.get_extension_for_oid',
                        side_effect=side_effect):
            crl = ca.get_crl(full_name=[full_name])
        self.assertCRL(crl, idp=idp, signer=ca, skip_authority_key_identifier=True)

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
            ca.get_crl(scope='foobar')


class CertificateTests(DjangoCAWithCertTestCase):
    def assertExtension(self, name, expected):
        for name, cert in list(self.cas.items()) + list(self.certs.items()):
            value = getattr(cert, name)
            exp = expected.get(cert)

            if exp is None:
                self.assertIsNone(value, cert)
            else:
                self.assertEqual(value, exp, cert)

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
            self.cas['child'], certs['child-cert']['csr']['pem'], [('CN', 'all.example.com')],
            san=['dirname:/C=AT/CN=example.com', 'email:user@example.com', 'fd00::1'])

        self.assertEqual(
            full.subject_alternative_name,
            SubjectAlternativeName({'value': [
                'DNS:all.example.com',
                'dirname:/C=AT/CN=example.com',
                'email:user@example.com',
                'IP:fd00::1',
            ]}))

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

    def test_ocsp_status(self):
        cert = self.certs['child-cert']
        self.assertEqual(cert.ocsp_status, 'good')

        for reason in ReasonFlags:
            cert.revoke(reason)
            if reason == ReasonFlags.unspecified:
                self.assertEqual(cert.ocsp_status, 'revoked')
            else:
                self.assertEqual(cert.ocsp_status, reason.name)

    def test_basic_constraints(self):
        for name, ca in self.cas.items():
            self.assertEqual(ca.basic_constraints, certs[name]['basic_constraints'])
            self.assertTrue(ca.basic_constraints.ca)
            self.assertEqual(ca.basic_constraints.pathlen, certs[name]['pathlen'])

        for name, cert in self.certs.items():
            bc = cert.basic_constraints
            self.assertEqual(bc, certs[name].get('basic_constraints'))

            if bc is not None:
                self.assertFalse(cert.basic_constraints.ca)
                self.assertIsNone(cert.basic_constraints.pathlen)

        # Make sure that some certs actually do have a value for this extension
        self.assertIsInstance(self.certs['all-extensions'].basic_constraints, BasicConstraints)
        self.assertFalse(self.certs['all-extensions'].basic_constraints.ca)
        self.assertIsNone(self.certs['no-extensions'].basic_constraints)

    def test_issuer_alternative_name(self):
        for name, ca in self.cas.items():
            self.assertIsNone(ca.issuer_alternative_name)

        for name, cert in self.certs.items():
            self.assertEqual(cert.issuer_alternative_name, certs[name].get('issuer_alternative_name'))

        # Make sure that some certs actually do have a value for this extension
        self.assertIsInstance(self.certs['all-extensions'].issuer_alternative_name, IssuerAlternativeName)
        self.assertIsNone(self.cas['child'].issuer_alternative_name)
        self.assertIsNone(self.certs['no-extensions'].issuer_alternative_name)

    def test_key_usage(self):
        for name, ca in self.cas.items():
            self.assertEqual(ca.key_usage, certs[name].get('key_usage'))

        for name, cert in self.certs.items():
            self.assertEqual(cert.key_usage, certs[name].get('key_usage'))

        # Make sure that some certs actually do have a value for this extension
        self.assertIsInstance(self.certs['all-extensions'].key_usage, KeyUsage)
        self.assertIsInstance(self.cas['child'].key_usage, KeyUsage)
        self.assertIsNone(self.certs['no-extensions'].key_usage, KeyUsage)

    def test_extended_key_usage(self):
        for name, ca in self.cas.items():
            self.assertEqual(ca.extended_key_usage, certs[name].get('extended_key_usage'))

        for name, cert in self.certs.items():
            self.assertEqual(cert.extended_key_usage, certs[name].get('extended_key_usage'))

        # Make sure that some certs actually do have a value for this extension
        self.assertIsInstance(self.certs['all-extensions'].extended_key_usage, ExtendedKeyUsage)
        self.assertIsInstance(self.cas['trustid_server_a52'].extended_key_usage, ExtendedKeyUsage)
        self.assertIsNone(self.cas['child'].extended_key_usage)
        self.assertIsNone(self.certs['no-extensions'].extended_key_usage)

    def test_crl_distribution_points(self):
        for name, ca in self.cas.items():
            expected = certs[name].get('crl_distribution_points')
            crl = ca.crl_distribution_points
            self.assertEqual(crl, expected)

        for name, cert in self.certs.items():
            expected = certs[name].get('crl_distribution_points')
            crl = cert.crl_distribution_points
            self.assertEqual(crl, expected)

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

    def test_authority_information_access(self):
        for name, ca in self.cas.items():
            self.assertEqual(ca.authority_information_access,
                             certs[name].get('authority_information_access'))

        for name, cert in self.certs.items():
            self.assertEqual(cert.authority_information_access,
                             certs[name].get('authority_information_access'))

        # Make sure that some certs actually do have a value for this extension
        self.assertIsInstance(self.certs['ecc-cert'].authority_information_access,
                              AuthorityInformationAccess)
        self.assertIsInstance(self.certs['all-extensions'].authority_information_access,
                              AuthorityInformationAccess)
        self.assertIsNone(self.certs['no-extensions'].authority_information_access)
        self.assertIsNone(self.cas['identrust_root_1'].authority_information_access)

    def test_authority_key_identifier(self):
        for name, ca in self.cas.items():
            self.assertEqual(ca.authority_key_identifier, certs[name].get('authority_key_identifier'))

        for name, cert in self.certs.items():
            self.assertEqual(cert.authority_key_identifier, certs[name].get('authority_key_identifier'))

        # Make sure that some certs actually do have a value for this extension
        self.assertIsInstance(self.certs['ecc-cert'].authority_key_identifier, AuthorityKeyIdentifier)
        self.assertIsInstance(self.certs['all-extensions'].authority_key_identifier, AuthorityKeyIdentifier)
        self.assertIsNone(self.certs['no-extensions'].authority_key_identifier)
        self.assertIsNone(self.cas['identrust_root_1'].authority_key_identifier)

    def test_subject_key_identifier(self):
        for name, ca in self.cas.items():
            self.assertEqual(ca.subject_key_identifier, certs[name].get('subject_key_identifier'))

        for name, cert in self.certs.items():
            self.assertEqual(cert.subject_key_identifier, certs[name].get('subject_key_identifier'))

        # Make sure that some certs actually do have a value for this extension
        self.assertIsInstance(self.certs['ecc-cert'].subject_key_identifier, SubjectKeyIdentifier)
        self.assertIsInstance(self.certs['all-extensions'].subject_key_identifier, SubjectKeyIdentifier)
        self.assertIsNone(self.certs['no-extensions'].subject_key_identifier)

    def test_hpkp_pin(self):
        # get hpkp pins using
        #   openssl x509 -in cert1.pem -pubkey -noout \
        #       | openssl rsa -pubin -outform der \
        #       | openssl dgst -sha256 -binary | base64
        for name, ca in self.cas.items():
            self.assertEqual(ca.hpkp_pin, certs[name]['hpkp'])
            self.assertIsInstance(ca.hpkp_pin, six.text_type)

        for name, cert in self.certs.items():
            self.assertEqual(cert.hpkp_pin, certs[name]['hpkp'])
            self.assertIsInstance(cert.hpkp_pin, six.text_type)

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

    ###############################################
    # Test extensions for all loaded certificates #
    ###############################################
    def test_name_constraints(self):
        for name, ca in self.cas.items():
            self.assertEqual(ca.name_constraints, certs[name].get('name_constraints'))

        for name, cert in self.certs.items():
            self.assertEqual(cert.name_constraints, certs[name].get('name_constraints'))

        # Make sure that some certs actually do have a value for this extension
        self.assertIsInstance(self.cas['letsencrypt_x1'].name_constraints, NameConstraints)
        self.assertIsInstance(self.certs['all-extensions'].name_constraints, NameConstraints)
        self.assertIsNone(self.certs['no-extensions'].name_constraints)

    def test_ocsp_no_check(self):
        for name, ca in self.cas.items():
            self.assertIsNone(ca.ocsp_no_check)  # Does not make sense in CAs, so check for None

        for name, cert in self.certs.items():
            self.assertEqual(cert.ocsp_no_check, certs[name].get('ocsp_no_check'))

        # Make sure that some certs actually do have a value for this extension
        self.assertIsInstance(self.certs['all-extensions'].ocsp_no_check, OCSPNoCheck)

    def test_precert_poison(self):
        for name, cert in self.certs.items():
            self.assertEqual(cert.precert_poison, certs[name].get('precert_poison'))

        # Make sure that some certs actually do have a value for this extension
        self.assertIsInstance(self.certs['all-extensions'].precert_poison, PrecertPoison)
        self.assertIsInstance(self.certs['cloudflare_1'].precert_poison, PrecertPoison)

    @unittest.skip('Cannot currently instantiate extensions, so no sense in testing this.')
    def test_precertificate_signed_certificate_timestamps(self):
        self.assertExtension('precertificate_signed_certificate_timestamps', {
            self.cert_letsencrypt_jabber_at: PrecertificateSignedCertificateTimestamps(),
        })

    def test_tls_feature(self):
        for name, ca in self.cas.items():
            self.assertEqual(ca.tls_feature, certs[ca.name].get('tls_feature'))

        for name, cert in self.certs.items():
            self.assertEqual(cert.tls_feature, certs[name].get('tls_feature'))

        self.assertIsInstance(self.certs['all-extensions'].tls_feature, TLSFeature)
