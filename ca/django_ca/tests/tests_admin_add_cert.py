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
# see <http://www.gnu.org/licenses/>

"""Test cases for adding certificates via the admin interface."""

import html
import unittest
from datetime import datetime
from datetime import timedelta

from django.conf import settings

from freezegun import freeze_time
from selenium.webdriver.support.select import Select

from .. import ca_settings
from ..extensions import BasicConstraints
from ..extensions import ExtendedKeyUsage
from ..extensions import KeyUsage
from ..extensions import SubjectAlternativeName
from ..extensions import TLSFeature
from ..models import Certificate
from ..models import CertificateAuthority
from ..profiles import profiles
from ..signals import post_issue_cert
from ..signals import pre_issue_cert
from ..utils import MULTIPLE_OIDS
from ..utils import NAME_OID_MAPPINGS
from .base import DjangoCAWithCertTestCase
from .base import SeleniumTestCase
from .base import certs
from .base import override_settings
from .base import override_tmpcadir
from .base import timestamps
from .tests_admin import CertificateAdminTestMixin


@freeze_time(timestamps['after_child'])
class AddCertificateTestCase(CertificateAdminTestMixin, DjangoCAWithCertTestCase):
    @override_tmpcadir()
    def test_get(self):
        response = self.client.get(self.add_url)
        self.assertEqual(response.status_code, 200)
        templates = [t.name for t in response.templates]
        self.assertIn('admin/django_ca/certificate/change_form.html', templates)
        self.assertIn('admin/change_form.html', templates)
        self.assertCSS(response, 'django_ca/admin/css/base.css')
        self.assertCSS(response, 'django_ca/admin/css/certificateadmin.css')

    @override_settings(CA_PROFILES={}, CA_DEFAULT_SUBJECT={})
    def test_get_dict(self):
        self.test_get()

    @override_tmpcadir(CA_DEFAULT_SUBJECT={})
    def test_add(self):
        cn = 'test-add.example.com'
        ca = self.cas['root']
        csr = certs['root-cert']['csr']['pem']

        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            response = self.client.post(self.add_url, data={
                'csr': csr,
                'ca': ca.pk,
                'profile': 'webserver',
                'subject_0': 'US',
                'subject_5': cn,
                'subject_alternative_name_1': True,
                'algorithm': 'SHA256',
                'expires': ca.expires.strftime('%Y-%m-%d'),
                'key_usage_0': ['digitalSignature', 'keyAgreement', ],
                'key_usage_1': True,
                'extended_key_usage_0': ['clientAuth', 'serverAuth', ],
                'extended_key_usage_1': False,
                'tls_feature_0': ['OCSPMustStaple', 'MultipleCertStatusRequest'],
                'tls_feature_1': False,
            })
        self.assertRedirects(response, self.changelist_url)
        self.assertEqual(pre.call_count, 1)

        cert = Certificate.objects.get(cn=cn)
        self.assertPostIssueCert(post, cert)
        self.assertSubject(cert.x509, [('C', 'US'), ('CN', cn)])
        self.assertIssuer(ca, cert)
        self.assertExtensions(cert, [
            ExtendedKeyUsage({'value': ['clientAuth', 'serverAuth']}),
            KeyUsage({'critical': True, 'value': ['digitalSignature', 'keyAgreement']}),
            SubjectAlternativeName({'value': ['DNS:%s' % cn]}),
            TLSFeature({'value': ['OCSPMustStaple', 'MultipleCertStatusRequest']}),
        ])

        self.assertEqual(cert.ca, ca)
        self.assertEqual(cert.csr, csr)
        self.assertEqual(cert.profile, 'webserver')

        # Some extensions are not set
        self.assertIsNone(cert.issuer_alternative_name)

        # Test that we can view the certificate
        response = self.client.get(self.change_url(cert.pk))
        self.assertEqual(response.status_code, 200)

    @override_tmpcadir()
    def test_required_subject(self):
        ca = self.cas['root']
        csr = certs['root-cert']['csr']['pem']
        cert_count = Certificate.objects.all().count()

        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            response = self.client.post(self.add_url, data={
                'csr': csr,
                'ca': ca.pk,
                'profile': 'webserver',
                'subject_0': 'US',
                'subject_alternative_name_1': True,
                'algorithm': 'SHA256',
                'expires': ca.expires.strftime('%Y-%m-%d'),
                'key_usage_0': ['digitalSignature', 'keyAgreement', ],
                'key_usage_1': True,
                'extended_key_usage_0': ['clientAuth', 'serverAuth', ],
                'extended_key_usage_1': False,
                'tls_feature_0': ['OCSPMustStaple', 'MultipleCertStatusRequest'],
                'tls_feature_1': False,
            })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertFalse(response.context['adminform'].form.is_valid())
        self.assertEqual(response.context['adminform'].form.errors,
                         {'subject': ['Enter a complete value.']})
        self.assertEqual(cert_count, Certificate.objects.all().count())

    @override_tmpcadir()
    def test_empty_subject(self):
        ca = self.cas['root']
        csr = certs['root-cert']['csr']['pem']
        cert_count = Certificate.objects.all().count()

        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            response = self.client.post(self.add_url, data={
                'csr': csr,
                'ca': ca.pk,
                'profile': 'webserver',
                'subject_0': '',
                'subject_1': '',
                'subject_2': '',
                'subject_3': '',
                'subject_4': '',
                'subject_5': '',
                'subject_6': '',
                'subject_alternative_name_1': True,
                'algorithm': 'SHA256',
                'expires': ca.expires.strftime('%Y-%m-%d'),
                'key_usage_0': ['digitalSignature', 'keyAgreement', ],
                'key_usage_1': True,
                'extended_key_usage_0': ['clientAuth', 'serverAuth', ],
                'extended_key_usage_1': False,
                'tls_feature_0': ['OCSPMustStaple', 'MultipleCertStatusRequest'],
                'tls_feature_1': False,
            })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertFalse(response.context['adminform'].form.is_valid())
        self.assertEqual(response.context['adminform'].form.errors,
                         {'subject': ['This field is required.']})
        self.assertEqual(cert_count, Certificate.objects.all().count())

    @override_tmpcadir(CA_DEFAULT_SUBJECT={})
    def test_add_no_key_usage(self):
        ca = self.cas['root']
        csr = certs['root-cert']['csr']['pem']
        cn = 'test-add2.example.com'
        san = 'test-san.example.com'

        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            response = self.client.post(self.add_url, data={
                'csr': csr,
                'ca': ca.pk,
                'profile': 'webserver',
                'subject_0': 'US',
                'subject_5': cn,
                'subject_alternative_name_0': san,
                'subject_alternative_name_1': True,
                'algorithm': 'SHA256',
                'expires': ca.expires.strftime('%Y-%m-%d'),
                'key_usage_0': [],
                'key_usage_1': False,
                'extended_key_usage_0': [],
                'extended_Key_usage_1': False,
            })
        self.assertEqual(pre.call_count, 1)
        self.assertRedirects(response, self.changelist_url)

        cert = Certificate.objects.get(cn=cn)
        self.assertPostIssueCert(post, cert)
        self.assertSubject(cert.x509, [('C', 'US'), ('CN', cn)])
        self.assertIssuer(ca, cert)
        self.assertEqual(cert.ca, ca)
        self.assertEqual(cert.csr, csr)

        # Some extensions are not set
        self.assertExtensions(cert, [
            SubjectAlternativeName({'value': ['DNS:%s' % san, 'DNS:%s' % cn]}),
        ])

        # Test that we can view the certificate
        response = self.client.get(self.change_url(cert.pk))
        self.assertEqual(response.status_code, 200)

    @override_tmpcadir(CA_DEFAULT_SUBJECT={})
    def test_add_with_password(self):
        ca = self.cas['pwd']
        csr = certs['pwd-cert']['csr']['pem']
        cn = 'with-password.example.com'

        # first post without password
        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            response = self.client.post(self.add_url, data={
                'csr': csr,
                'ca': ca.pk,
                'profile': 'webserver',
                'subject_0': 'US',
                'subject_5': cn,
                'subject_alternative_name_1': True,
                'algorithm': 'SHA256',
                'expires': ca.expires.strftime('%Y-%m-%d'),
                'key_usage_0': ['digitalSignature', 'keyAgreement', ],
                'key_usage_1': True,
                'extended_key_usage_0': ['clientAuth', 'serverAuth', ],
                'extended_key_usage_1': False,
            })
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertFalse(response.context['adminform'].form.is_valid())
        self.assertEqual(response.context['adminform'].form.errors,
                         {'password': ['Password was not given but private key is encrypted']})

        # now post with a false password
        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            response = self.client.post(self.add_url, data={
                'csr': csr,
                'ca': ca.pk,
                'profile': 'webserver',
                'subject_0': 'US',
                'subject_5': cn,
                'subject_alternative_name_1': True,
                'algorithm': 'SHA256',
                'expires': ca.expires.strftime('%Y-%m-%d'),
                'key_usage_0': ['digitalSignature', 'keyAgreement', ],
                'key_usage_1': True,
                'extended_key_usage_0': ['clientAuth', 'serverAuth', ],
                'extended_key_usage_1': False,
                'password': 'wrong',
            })
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertFalse(response.context['adminform'].form.is_valid())
        self.assertEqual(response.context['adminform'].form.errors,
                         {'password': ['Bad decrypt. Incorrect password?']})

        # post with correct password!
        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            response = self.client.post(self.add_url, data={
                'csr': csr,
                'ca': ca.pk,
                'profile': 'webserver',
                'subject_0': 'US',
                'subject_5': cn,
                'subject_alternative_name_1': True,
                'algorithm': 'SHA256',
                'expires': ca.expires.strftime('%Y-%m-%d'),
                'key_usage_0': ['digitalSignature', 'keyAgreement', ],
                'key_usage_1': True,
                'extended_key_usage_0': ['clientAuth', 'serverAuth', ],
                'extended_key_usage_1': False,
                'password': certs['pwd']['password'].decode('utf-8'),
            })
        self.assertEqual(pre.call_count, 1)
        self.assertRedirects(response, self.changelist_url)

        cert = Certificate.objects.get(cn=cn)
        self.assertPostIssueCert(post, cert)
        self.assertSubject(cert.x509, [('C', 'US'), ('CN', cn)])
        self.assertIssuer(ca, cert)
        self.assertAuthorityKeyIdentifier(ca, cert)
        self.assertEqual(cert.subject_alternative_name,
                         SubjectAlternativeName({'value': ['DNS:%s' % cn]}))
        self.assertEqual(cert.basic_constraints,
                         BasicConstraints({'critical': True, 'value': {'ca': False}}))
        self.assertEqual(cert.key_usage,
                         KeyUsage({'critical': True, 'value': ['digitalSignature', 'keyAgreement']}))
        self.assertEqual(cert.extended_key_usage,
                         ExtendedKeyUsage({'value': ['clientAuth', 'serverAuth']}))
        self.assertEqual(cert.ca, ca)
        self.assertEqual(cert.csr, csr)

        # Some extensions are not set
        self.assertIsNone(cert.certificate_policies)
        self.assertIsNone(cert.issuer_alternative_name)
        self.assertIsNone(cert.precertificate_signed_certificate_timestamps)
        self.assertIsNone(cert.tls_feature)

        # Test that we can view the certificate
        response = self.client.get(self.change_url(cert.pk))
        self.assertEqual(response.status_code, 200)

    @override_tmpcadir()
    def test_wrong_csr(self):
        ca = self.cas['root']
        cn = 'test-add-wrong-csr.example.com'

        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            response = self.client.post(self.add_url, data={
                'csr': 'whatever',
                'ca': ca.pk,
                'profile': 'webserver',
                'subject_0': 'US',
                'subject_5': cn,
                'subject_alternative_name_1': True,
                'algorithm': 'SHA256',
                'expires': ca.expires.strftime('%Y-%m-%d'),
                'key_usage_0': ['digitalSignature', 'keyAgreement', ],
                'key_usage_1': True,
                'extended_key_usage_0': ['clientAuth', 'serverAuth', ],
                'extended_key_usage_1': False,
            })
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Enter a valid CSR (in PEM format).", response.content.decode('utf-8'))
        self.assertFalse(response.context['adminform'].form.is_valid())
        self.assertEqual(response.context['adminform'].form.errors,
                         {'csr': ['Enter a valid CSR (in PEM format).']})

        with self.assertRaises(Certificate.DoesNotExist):
            Certificate.objects.get(cn=cn)

    @override_tmpcadir()
    def test_wrong_algorithm(self):
        ca = self.cas['root']
        csr = certs['pwd-cert']['csr']['pem']
        cn = 'test-add-wrong-algo.example.com'

        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            response = self.client.post(self.add_url, data={
                'csr': csr,
                'ca': ca.pk,
                'profile': 'webserver',
                'subject_0': 'US',
                'subject_5': cn,
                'subject_alternative_name_1': True,
                'algorithm': 'wrong algo',
                'expires': ca.expires.strftime('%Y-%m-%d'),
                'key_usage_0': ['digitalSignature', 'keyAgreement', ],
                'key_usage_1': True,
                'extended_key_usage_0': ['clientAuth', 'serverAuth', ],
                'extended_key_usage_1': False,
            })
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertEqual(response.status_code, 200)

        self.assertFalse(response.context['adminform'].form.is_valid())
        self.assertEqual(
            response.context['adminform'].form.errors,
            {'algorithm': ['Select a valid choice. wrong algo is not one of the available choices.']})

        with self.assertRaises(Certificate.DoesNotExist):
            Certificate.objects.get(cn=cn)

    @override_tmpcadir()
    def test_expires_in_the_past(self):
        ca = self.cas['root']
        csr = certs['pwd-cert']['csr']['pem']
        cn = 'test-expires-in-the-past.example.com'
        expires = datetime.now() - timedelta(days=3)

        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            response = self.client.post(self.add_url, data={
                'csr': csr,
                'ca': ca.pk,
                'profile': 'webserver',
                'subject_0': 'US',
                'subject_5': cn,
                'subject_alternative_name_1': True,
                'algorithm': 'SHA256',
                'expires': expires.strftime('%Y-%m-%d'),
                'key_usage_0': ['digitalSignature', 'keyAgreement', ],
                'key_usage_1': True,
                'extended_key_usage_0': ['clientAuth', 'serverAuth', ],
                'extended_key_usage_1': False,
            })
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Certificate cannot expire in the past.', response.content.decode('utf-8'))
        self.assertFalse(response.context['adminform'].form.is_valid())
        self.assertEqual(response.context['adminform'].form.errors,
                         {'expires': ['Certificate cannot expire in the past.']})

        with self.assertRaises(Certificate.DoesNotExist):
            Certificate.objects.get(cn=cn)

    @override_tmpcadir()
    def test_expires_too_late(self):
        ca = self.cas['root']
        csr = certs['pwd-cert']['csr']['pem']
        cn = 'test-expires-too-late.example.com'
        expires = ca.expires + timedelta(days=3)
        correct_expires = ca.expires.strftime('%Y-%m-%d')
        error = 'CA expires on %s, certificate must not expire after that.' % correct_expires

        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            response = self.client.post(self.add_url, data={
                'csr': csr,
                'ca': ca.pk,
                'profile': 'webserver',
                'subject_0': 'US',
                'subject_5': cn,
                'subject_alternative_name_1': True,
                'algorithm': 'SHA256',
                'expires': expires.strftime('%Y-%m-%d'),
                'key_usage_0': ['digitalSignature', 'keyAgreement', ],
                'key_usage_1': True,
                'extended_key_usage_0': ['clientAuth', 'serverAuth', ],
                'extended_key_usage_1': False,
            })
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertEqual(response.status_code, 200)
        self.assertIn(error, response.content.decode('utf-8'))
        self.assertFalse(response.context['adminform'].form.is_valid())
        self.assertEqual(response.context['adminform'].form.errors, {'expires': [error]})

        with self.assertRaises(Certificate.DoesNotExist):
            Certificate.objects.get(cn=cn)

    @override_tmpcadir()
    def test_invalid_cn_in_san(self):
        # If you submit a CommonName that is not parseable as SubjectAlternativeName, but check "CN in SAN",
        # we need to throw a form error.
        #   https://github.com/mathiasertl/django-ca/issues/62
        cn = 'Foo Bar'
        error = 'The CommonName cannot be parsed as general name. Either change the CommonName or do not include it.'  # NOQA
        ca = self.cas['root']
        csr = certs['root-cert']['csr']['pem']

        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            response = self.client.post(self.add_url, data={
                'csr': csr,
                'ca': ca.pk,
                'profile': 'webserver',
                'subject_0': 'US',
                'subject_5': cn,
                'subject_alternative_name_1': True,  # cn_in_san
                'algorithm': 'SHA256',
                'expires': ca.expires.strftime('%Y-%m-%d'),
                'key_usage_0': ['digitalSignature', 'keyAgreement', ],
                'key_usage_1': True,
                'extended_key_usage_0': ['clientAuth', 'serverAuth', ],
                'extended_key_usage_1': False,
                'tls_feature_0': ['OCSPMustStaple', 'MultipleCertStatusRequest'],
                'tls_feature_1': False,
            })
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertEqual(response.status_code, 200)
        self.assertIn(html.escape(error), response.content.decode('utf-8'))
        self.assertFalse(response.context['adminform'].form.is_valid())
        self.assertEqual(response.context['adminform'].form.errors, {'subject_alternative_name': [error]})

        with self.assertRaises(Certificate.DoesNotExist):
            Certificate.objects.get(cn=cn)

    def test_add_no_cas(self):
        ca = self.cas['root']
        csr = certs['pwd-cert']['csr']['pem']
        CertificateAuthority.objects.update(enabled=False)
        response = self.client.get(self.add_url)
        self.assertEqual(response.status_code, 403)

        cn = 'test-add-no-cas.example.com'
        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            response = self.client.post(self.add_url, data={
                'csr': csr,
                'ca': ca.pk,
                'profile': 'webserver',
                'subject_0': 'US',
                'subject_5': cn,
                'subject_alternative_name_1': True,
                'algorithm': 'SHA256',
                'expires': ca.expires.strftime('%Y-%m-%d'),
                'key_usage_0': ['digitalSignature', 'keyAgreement', ],
                'key_usage_1': True,
                'extended_key_usage_0': ['clientAuth', 'serverAuth', ],
                'extended_key_usage_1': False,
            })
        self.assertEqual(response.status_code, 403)
        self.assertFalse(pre.called)
        self.assertFalse(post.called)

    def test_add_unusable_cas(self):
        ca = self.cas['root']
        csr = certs['pwd-cert']['csr']['pem']
        CertificateAuthority.objects.update(private_key_path='not/exist/add-unusable-cas')

        # check that we have some enabled CAs, just to make sure this test is really useful
        self.assertTrue(CertificateAuthority.objects.filter(enabled=True).exists())

        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            response = self.client.get(self.add_url)
        self.assertEqual(response.status_code, 403)
        self.assertFalse(pre.called)
        self.assertFalse(post.called)

        cn = 'test-add.example.com'
        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            response = self.client.post(self.add_url, data={
                'csr': csr,
                'ca': ca.pk,
                'profile': 'webserver',
                'subject_0': 'US',
                'subject_5': cn,
                'subject_alternative_name_1': True,
                'algorithm': 'SHA256',
                'expires': ca.expires.strftime('%Y-%m-%d'),
                'key_usage_0': ['digitalSignature', 'keyAgreement', ],
                'key_usage_1': True,
                'extended_key_usage_0': ['clientAuth', 'serverAuth', ],
                'extended_key_usage_1': False,
            })
        self.assertEqual(response.status_code, 403)
        self.assertFalse(pre.called)
        self.assertFalse(post.called)


@unittest.skipIf(settings.SKIP_SELENIUM_TESTS, 'Selenium tests skipped.')
class AddCertificateSeleniumTestCase(CertificateAdminTestMixin, SeleniumTestCase):
    """Some Selenium based test cases to test the client side javascript code."""

    def get_expected(self, profile, extension_class, default=None):
        """Get expected value for a given extension for the given profile."""
        if extension_class.key in profile.extensions:
            return profile.extensions[extension_class.key].serialize()
        return {'value': default, 'critical': extension_class.default_critical}

    def assertProfile(self, profile, ku_select, ku_critical, eku_select,  # pylint: disable=invalid-name
                      eku_critical, tf_select, tf_critical, subject, cn_in_san):
        """Assert that the admin form equals the given profile."""
        profile = profiles[profile]

        ku_expected = self.get_expected(profile, KeyUsage, [])
        ku_selected = [o.get_attribute('value') for o in ku_select.all_selected_options]
        self.assertCountEqual(ku_expected['value'], ku_selected)
        self.assertEqual(ku_expected['critical'], ku_critical.is_selected())

        eku_expected = self.get_expected(profile, ExtendedKeyUsage, [])
        eku_selected = [o.get_attribute('value') for o in eku_select.all_selected_options]
        self.assertCountEqual(eku_expected['value'], eku_selected)
        self.assertEqual(eku_expected['critical'], eku_critical.is_selected())

        tf_selected = [o.get_attribute('value') for o in tf_select.all_selected_options]
        tf_expected = self.get_expected(profile, TLSFeature, [])
        self.assertCountEqual(tf_expected.get('value', []), tf_selected)
        self.assertEqual(tf_expected.get('critical', False), tf_critical.is_selected())

        self.assertEqual(profile.cn_in_san, cn_in_san.is_selected())

        for key, field in subject.items():
            value = field.get_attribute('value')

            # OIDs that can occur multiple times are stored as list in subject, so we wrap it
            if NAME_OID_MAPPINGS[key] in MULTIPLE_OIDS:
                value = [value]

            self.assertEqual(value, profile.subject.get(key, ''))

    def clear_form(self, ku_select, ku_critical, eku_select, eku_critical, tf_select, tf_critical, cn_in_san,
                   subject_fields):
        """Clear the form."""
        ku_select.deselect_all()
        eku_select.deselect_all()
        tf_select.deselect_all()

        if ku_critical.is_selected():
            ku_critical.click()
        if eku_critical.is_selected():
            eku_critical.click()
        if tf_critical.is_selected():
            tf_critical.click()
        if cn_in_san.is_selected():
            cn_in_san.click()
        for field in subject_fields.values():
            field.clear()

    @override_tmpcadir()
    def test_paste_csr_test(self):
        """Test that pasting a CSR shows text next to subject input fields."""
        self.load_usable_cas()
        self.login()

        self.selenium.get('%s%s' % (self.live_server_url, self.add_url))

        cert = certs['all-extensions']
        csr = self.find('textarea#id_csr')
        csr.send_keys(cert['csr']['pem'])

        subject_fields = {
            'C': self.find('.field-subject #country'),
            'ST': self.find('.field-subject #state'),
            'L': self.find('.field-subject #location'),
            'O': self.find('.field-subject #organization'),
            'OU': self.find('.field-subject #organizational-unit'),
            'CN': self.find('.field-subject #commonname'),
            'emailAddress': self.find('.field-subject #e-mail'),
        }

        for key, elem in subject_fields.items():
            input_elem = elem.find_element_by_css_selector('input')
            csr_copy = elem.find_element_by_css_selector('.from-csr-copy')
            from_csr = elem.find_element_by_css_selector('.from-csr-value')
            self.assertEqual(from_csr.text, cert['csr_subject'][key])

            # click the 'copy' button
            csr_copy.click()

            self.assertEqual(from_csr.text, input_elem.get_attribute('value'))

    @override_tmpcadir()
    def test_select_profile(self):
        """Test that selecting the profile modifies the extensions."""

        self.load_usable_cas()
        self.login()

        self.selenium.get('%s%s' % (self.live_server_url, self.add_url))
        select = Select(self.find('select#id_profile'))
        ku_select = Select(self.find('select#id_key_usage_0'))
        ku_critical = self.find('input#id_key_usage_1')
        eku_select = Select(self.find('select#id_extended_key_usage_0'))
        eku_critical = self.find('input#id_extended_key_usage_1')
        tf_select = Select(self.find('select#id_tls_feature_0'))
        tf_critical = self.find('input#id_tls_feature_1')

        subject_fields = {
            'C': self.find('.field-subject #country input'),
            'ST': self.find('.field-subject #state input'),
            'L': self.find('.field-subject #location input'),
            'O': self.find('.field-subject #organization input'),
            'OU': self.find('.field-subject #organizational-unit input'),
            'CN': self.find('.field-subject #commonname input'),
            'emailAddress': self.find('.field-subject #e-mail input'),
        }
        cn_in_san = self.find('input#id_subject_alternative_name_1')

        # test that the default profile is preselected
        self.assertEqual([ca_settings.CA_DEFAULT_PROFILE],
                         [o.get_attribute('value') for o in select.all_selected_options])

        # assert that the values from the default profile are pre-loaded
        self.assertProfile(ca_settings.CA_DEFAULT_PROFILE, ku_select, ku_critical, eku_select, eku_critical,
                           tf_select, tf_critical, subject_fields, cn_in_san)

        for option in select.options:
            # first, clear everything to make sure that the profile *sets* everything
            self.clear_form(ku_select, ku_critical, eku_select, eku_critical, tf_select, tf_critical,
                            cn_in_san, subject_fields)

            value = option.get_attribute("value")
            if not value:
                continue
            option.click()

            self.assertProfile(value, ku_select, ku_critical, eku_select, eku_critical,
                               tf_select, tf_critical, subject_fields, cn_in_san)

            # now fill everything with dummy values to test the other way round
            # pylint: disable=expression-not-assigned
            [ku_select.select_by_value(o.get_attribute('value')) for o in ku_select.options]
            [eku_select.select_by_value(o.get_attribute('value')) for o in eku_select.options]
            [tf_select.select_by_value(o.get_attribute('value')) for o in tf_select.options]
            # pylint: enable=expression-not-assigned

            if not ku_critical.is_selected():
                ku_critical.click()
            if not eku_critical.is_selected():
                eku_critical.click()
            if not tf_critical.is_selected():
                tf_critical.click()
            if not cn_in_san.is_selected():
                cn_in_san.click()

            for field in subject_fields.values():
                field.clear()
                field.send_keys('testdata')

            # select empty element in profile select, then select profile again
            select.select_by_value(ca_settings.CA_DEFAULT_PROFILE)
            self.clear_form(ku_select, ku_critical, eku_select, eku_critical, tf_select, tf_critical,
                            cn_in_san, subject_fields)
            option.click()

            # see that all the right things are selected
            self.assertProfile(value, ku_select, ku_critical, eku_select, eku_critical,
                               tf_select, tf_critical, subject_fields, cn_in_san)
