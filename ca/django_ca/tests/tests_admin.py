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
# see <http://www.gnu.org/licenses/>

import json
import unittest
from datetime import datetime
from datetime import timedelta

from freezegun import freeze_time

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.extensions import Extension
from cryptography.x509.extensions import UnrecognizedExtension
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.oid import ObjectIdentifier

import django
from django.contrib.auth.models import Permission
from django.contrib.auth.models import User
from django.templatetags.static import static
from django.test import Client
from django.urls import reverse
from django.utils.encoding import force_text
from django.utils.six.moves.urllib.parse import quote

from django_webtest import WebTestMixin

from .. import ca_settings
from ..constants import ReasonFlags
from ..extensions import BasicConstraints
from ..extensions import ExtendedKeyUsage
from ..extensions import KeyUsage
from ..extensions import SubjectAlternativeName
from ..extensions import TLSFeature
from ..models import Certificate
from ..models import CertificateAuthority
from ..models import Watcher
from ..signals import post_issue_cert
from ..signals import post_revoke_cert
from ..signals import pre_issue_cert
from ..signals import pre_revoke_cert
from ..utils import SUBJECT_FIELDS
from .base import DjangoCATestCase
from .base import DjangoCAWithCertTestCase
from .base import DjangoCAWithGeneratedCertsTestCase
from .base import SeleniumTestCase
from .base import certs
from .base import override_settings
from .base import override_tmpcadir
from .base import timestamps

try:
    import unittest.mock as mock
except ImportError:
    import mock


class AdminTestMixin(object):
    def setUp(self):
        self.user = User.objects.create_superuser(username='user', password='password',
                                                  email='user@example.com')
        self.add_url = reverse('admin:django_ca_certificate_add')
        self.changelist_url = reverse('admin:django_ca_certificate_changelist')
        self.client = Client()
        self.client.force_login(self.user)
        super(AdminTestMixin, self).setUp()

    def assertCSS(self, response, path):
        css = '<link href="%s" type="text/css" media="all" rel="stylesheet" />' % static(path)
        self.assertInHTML(css, response.content.decode('utf-8'), 1)

    def change_url(self, pk=None):
        if pk is None:
            pk = self.certs['root-cert'].pk

        return reverse('admin:django_ca_certificate_change', args=(pk, ))

    def assertChangeResponse(self, response):
        self.assertEqual(response.status_code, 200)

        templates = [t.name for t in response.templates]
        self.assertIn('django_ca/admin/change_form.html', templates)
        self.assertIn('admin/change_form.html', templates)
        self.assertCSS(response, 'django_ca/admin/css/base.css')
        self.assertCSS(response, 'django_ca/admin/css/certificateadmin.css')

    def assertRequiresLogin(self, response, **kwargs):
        expected = '%s?next=%s' % (reverse('admin:login'), quote(response.wsgi_request.get_full_path()))
        self.assertRedirects(response, expected, **kwargs)


class ChangelistTestCase(AdminTestMixin, DjangoCAWithGeneratedCertsTestCase):
    """Test the changelist view."""

    def assertResponse(self, response, certs=None):
        if certs is None:
            certs = []

        self.assertEqual(response.status_code, 200)
        self.assertCSS(response, 'django_ca/admin/css/base.css')
        self.assertCSS(response, 'django_ca/admin/css/certificateadmin.css')
        self.assertEqual(set(response.context['cl'].result_list), set(certs))

    def test_get(self):
        # Just make sure that viewing the changelist doesn't yield an exception
        self.load_all_certs()  # load all certs here
        response = self.client.get(self.changelist_url)
        self.assertResponse(response, self.certs.values())

    @freeze_time(timestamps['everything_valid'])
    def test_status_all_valid(self):
        self.client.force_login(self.user)

        response = self.client.get('%s?status=valid' % self.changelist_url)
        self.assertResponse(response, self.certs.values())
        response = self.client.get('%s?status=expired' % self.changelist_url)
        self.assertResponse(response, [])
        response = self.client.get('%s?status=revoked' % self.changelist_url)
        self.assertResponse(response, [])

    @freeze_time(timestamps['ca_certs_expired'])
    def test_status_ca_certs_expired(self):
        self.client.force_login(self.user)

        response = self.client.get('%s?status=valid' % self.changelist_url)
        self.assertResponse(response, [
            self.certs['profile-client'],
            self.certs['profile-server'],
            self.certs['profile-webserver'],
            self.certs['profile-enduser'],
            self.certs['profile-ocsp'],
            self.certs['no-extensions'],
            self.certs['all-extensions'],
            self.certs['alt-extensions'],
        ])
        response = self.client.get('%s?status=expired' % self.changelist_url)
        self.assertResponse(response, [
            self.certs['root-cert'],
            self.certs['pwd-cert'],
            self.certs['ecc-cert'],
            self.certs['dsa-cert'],
            self.certs['child-cert'],
        ])
        response = self.client.get('%s?status=revoked' % self.changelist_url)
        self.assertResponse(response, [])

    @freeze_time(timestamps['everything_expired'])
    def test_status_everything_expired(self):
        self.client.force_login(self.user)

        response = self.client.get('%s?status=valid' % self.changelist_url)
        self.assertResponse(response, [])
        response = self.client.get('%s?status=expired' % self.changelist_url)
        self.assertResponse(response, self.certs.values())
        response = self.client.get('%s?status=revoked' % self.changelist_url)
        self.assertResponse(response, [])

    @freeze_time(timestamps['everything_valid'])
    def test_status_revoked(self):
        self.client.force_login(self.user)
        self.certs['root-cert'].revoke()

        valid = [c for c in self.certs.values() if c != self.certs['root-cert']]

        response = self.client.get('%s?status=valid' % self.changelist_url)
        self.assertResponse(response, valid)
        response = self.client.get('%s?status=expired' % self.changelist_url)
        self.assertResponse(response, [])
        response = self.client.get('%s?status=revoked' % self.changelist_url)
        self.assertResponse(response, [self.certs['root-cert']])

    def test_unauthorized(self):
        client = Client()
        response = client.get(self.changelist_url)
        self.assertRequiresLogin(response)


@override_settings(USE_TZ=True)
class ChangelistWithTZTestCase(ChangelistTestCase):
    pass


class RevokeActionTestCase(AdminTestMixin, DjangoCAWithGeneratedCertsTestCase):
    """Test the "revoke" action in the changelist."""

    def test_basic(self):
        self.assertNotRevoked(self.certs['root-cert'])

        data = {
            'action': 'revoke', '_selected_action': [self.certs['root-cert'].pk],
        }
        response = self.client.post(self.changelist_url, data)
        self.assertRedirects(response, self.changelist_url)
        self.assertRevoked(self.certs['root-cert'])

        # revoking revoked certs does nothing:
        response = self.client.post(self.changelist_url, data)
        self.assertRedirects(response, self.changelist_url)
        self.assertRevoked(self.certs['root-cert'])

    def test_permissions(self):
        cert = self.certs['root-cert']
        data = {
            'action': 'revoke', '_selected_action': [cert.pk],
        }

        # make an anonymous request
        client = Client()
        response = client.post(self.changelist_url, data)
        self.assertRequiresLogin(response)

        # cert is not revoked
        cert = Certificate.objects.get(serial=cert.serial)
        self.assertFalse(cert.revoked)
        self.assertIsNone(cert.revoked_reason)

        # test with a logged in user, but not staff
        user = User.objects.create_user(username='staff', password='password', email='staff@example.com')
        client.force_login(user=user)

        response = client.post(self.changelist_url, data)
        self.assertRequiresLogin(response)
        self.assertNotRevoked(cert)

        # make the user "staff"
        user.is_staff = True
        user.save()
        self.assertTrue(User.objects.get(username='staff').is_staff)  # really is staff, right?
        response = client.post(self.changelist_url, data)
        self.assertEqual(response.status_code, 403)
        self.assertNotRevoked(cert)

        # now give appropriate permission
        p = Permission.objects.get(codename='change_certificate')
        user.user_permissions.add(p)
        response = client.post(self.changelist_url, data)
        self.assertRevoked(cert)


class ChangeTestCase(AdminTestMixin, DjangoCAWithCertTestCase):
    def test_basic(self):
        # Just assert that viewing a certificate does not throw an exception
        for name, cert in self.certs.items():
            response = self.client.get(self.change_url(cert.pk))
            self.assertChangeResponse(response)

    def test_revoked(self):
        # view a revoked certificate (fieldsets are collapsed differently)
        self.certs['root-cert'].revoke()

        response = self.client.get(self.change_url())
        self.assertChangeResponse(response)

        if django.VERSION < (2, 0):  # pragma: django<2.0
            cls = 'field-box'
        else:
            cls = 'fieldBox'

        self.assertContains(response, text='''<div class="%s field-revoked"><label>Revoked:</label>
                     <div class="readonly"><img src="/static/admin/img/icon-yes.svg" alt="True"></div>
                </div>''' % cls, html=True)

    def test_no_san(self):
        # Test display of a certificate with no SAN
        cert = self.certs['no-extensions']
        response = self.client.get(self.change_url(cert.pk))
        self.assertChangeResponse(response)
        self.assertContains(response, text='''
<div class="form-row field-subject_alternative_name">
    <div>
        <label>SubjectAltName:</label>
        <div class="readonly">&lt;none&gt;</div>
    </div>
</div>
''', html=True)

    def test_change_watchers(self):
        cert = self.certs['root-cert']
        cert = Certificate.objects.get(serial=cert.serial)
        watcher = Watcher.objects.create(name='User', mail='user@example.com')

        response = self.client.post(self.change_url(), data={
            'watchers': [watcher.pk],
        })

        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, self.changelist_url)
        self.assertEqual(list(cert.watchers.all()), [watcher])

    def test_unsupported_extensions(self):
        self.maxDiff = None
        cert = self.certs['all-extensions']
        # Act as if no extensions is recognized, to see what happens if we'd encounter an unknown extension.
        with mock.patch.object(Certificate, 'OID_MAPPING', {}), self.assertLogs() as logs:
            response = self.client.get(self.change_url(cert.pk))
            self.assertChangeResponse(response)

        log_msg = 'WARNING:django_ca.models:Unknown extension encountered: %s'
        expected = [
            log_msg % 'AuthorityInfoAccess (1.3.6.1.5.5.7.1.1)',
            log_msg % 'AuthorityKeyIdentifier (2.5.29.35)',
            log_msg % 'BasicConstraints (2.5.29.19)',
            log_msg % 'CRLDistributionPoints (2.5.29.31)',
            log_msg % 'ExtendedKeyUsage (2.5.29.37)',
            log_msg % 'IssuerAltName (2.5.29.18)',
            log_msg % 'KeyUsage (2.5.29.15)',
            log_msg % 'NameConstraints (2.5.29.30)',
            log_msg % 'OCSPNoCheck (1.3.6.1.5.5.7.48.1.5)',
            log_msg % 'PrecertPoison (1.3.6.1.4.1.11129.2.4.3)',
            log_msg % 'SubjectAltName (2.5.29.17)',
            log_msg % 'SubjectKeyIdentifier (2.5.29.14)',
            log_msg % 'TLSFeature (1.3.6.1.5.5.7.1.24)',
        ]

        self.assertEqual(logs.output, sorted(expected))

    @unittest.skipUnless(
        ca_settings.OPENSSL_SUPPORTS_SCT,
        'Older versions of OpenSSL/LibreSSL do not recognize this extension anyway.')
    def test_unsupported_sct(self):
        # Test return value for older versions of OpenSSL
        cert = self.certs['letsencrypt_x3-cert']

        oid = ObjectIdentifier('1.1.1.1')
        value = UnrecognizedExtension(oid, b'foo')
        ext = Extension(oid=oid, critical=False, value=value)
        orig_func = cert.x509.extensions.get_extension_for_oid

        def side_effect(key):
            if key == ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS:
                return ext
            else:
                return orig_func(key)

        with mock.patch('cryptography.x509.extensions.Extensions.get_extension_for_oid',
                        side_effect=side_effect):
            response = self.client.get(self.change_url(cert.pk))
            self.assertChangeResponse(response)

    def test_unknown_object(self):
        response = self.client.get(self.change_url(1234))
        self.assertEqual(response.status_code, 302)


@freeze_time(timestamps['after_child'])
class AddTestCase(AdminTestMixin, DjangoCAWithCertTestCase):
    @override_tmpcadir()
    def test_get(self):
        response = self.client.get(self.add_url)
        self.assertEqual(response.status_code, 200)
        templates = [t.name for t in response.templates]
        self.assertIn('django_ca/admin/change_form.html', templates)
        self.assertIn('admin/change_form.html', templates)
        self.assertCSS(response, 'django_ca/admin/css/base.css')
        self.assertCSS(response, 'django_ca/admin/css/certificateadmin.css')

    @override_settings(CA_PROFILES={}, CA_DEFAULT_SUBJECT={})
    def test_get_dict(self):
        self.test_get()

    @override_tmpcadir()
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
        self.assertAuthorityKeyIdentifier(ca, cert)
        self.assertEqual(cert.subject_alternative_name, SubjectAlternativeName('DNS:%s' % cn))
        self.assertEqual(cert.basic_constraints, BasicConstraints('critical,CA:FALSE'))
        self.assertEqual(cert.key_usage, KeyUsage('critical,digitalSignature,keyAgreement'))
        self.assertEqual(cert.extended_key_usage, ExtendedKeyUsage('clientAuth,serverAuth'))
        self.assertEqual(cert.tls_feature, TLSFeature('OCSPMustStaple,MultipleCertStatusRequest'))
        self.assertEqual(cert.ca, ca)
        self.assertEqual(cert.csr, csr)

        # Some extensions are not set
        self.assertIsNone(cert.issuer_alternative_name)

        # Test that we can view the certificate
        response = self.client.get(self.change_url(cert.pk))
        self.assertEqual(response.status_code, 200)

    @override_tmpcadir()
    def test_required_subject(self):
        ca = self.cas['root']
        csr = certs['root-cert']['csr']['pem']

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

    @override_tmpcadir()
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
        self.assertAuthorityKeyIdentifier(ca, cert)
        self.assertEqual(cert.subject_alternative_name, SubjectAlternativeName('DNS:%s,DNS:%s' % (cn, san)))
        self.assertEqual(cert.basic_constraints, BasicConstraints('critical,CA:FALSE'))
        self.assertEqual(cert.ca, ca)
        self.assertEqual(cert.csr, csr)

        # Some extensions are not set
        self.assertIsNone(cert.certificate_policies)
        self.assertIsNone(cert.extended_key_usage)
        self.assertIsNone(cert.issuer_alternative_name)
        self.assertIsNone(cert.key_usage)
        self.assertIsNone(cert.precertificate_signed_certificate_timestamps)
        self.assertIsNone(cert.tls_feature)

        # Test that we can view the certificate
        response = self.client.get(self.change_url(cert.pk))
        self.assertEqual(response.status_code, 200)

    @override_tmpcadir()
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
        self.assertEqual(cert.subject_alternative_name, SubjectAlternativeName('DNS:%s' % cn))
        self.assertEqual(cert.basic_constraints, BasicConstraints('critical,CA:FALSE'))
        self.assertEqual(cert.key_usage, KeyUsage('critical,digitalSignature,keyAgreement'))
        self.assertEqual(cert.extended_key_usage, ExtendedKeyUsage('clientAuth,serverAuth'))
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


class CSRDetailTestCase(AdminTestMixin, DjangoCATestCase):
    def setUp(self):
        self.url = reverse('admin:django_ca_certificate_csr_details')
        self.csr_pem = certs['root-cert']['csr']['pem']
        super(CSRDetailTestCase, self).setUp()

    def test_basic(self):
        response = self.client.post(self.url, data={'csr': self.csr_pem})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content.decode('utf-8')),
                         {'subject': {'C': 'AU', 'O': 'Internet Widgits Pty Ltd', 'ST': 'Some-State'}})

    def test_fields(self):
        subject = [(f, 'AT' if f == 'C' else 'test-%s' % f) for f in SUBJECT_FIELDS]
        key, csr = self.create_csr(subject)
        csr_pem = csr.public_bytes(Encoding.PEM).decode('utf-8')

        response = self.client.post(self.url, data={'csr': csr_pem})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content.decode('utf-8')), {'subject': {
            'C': 'AT', 'CN': 'test-CN', 'L': 'test-L', 'O': 'test-O', 'OU': 'test-OU', 'ST':
            'test-ST', 'emailAddress': 'test-emailAddress'}})

    def test_bad_request(self):
        response = self.client.post(self.url, data={'csr': 'foobar'})
        self.assertEqual(response.status_code, 400)

    def test_anonymous(self):
        client = Client()

        response = client.post(self.url, data={'csr': self.csr_pem})
        self.assertRequiresLogin(response)

    def test_plain_user(self):
        # User isn't staff and has no permissions
        client = Client()
        user = User.objects.create_user(username='plain', password='password', email='plain@example.com')
        client.force_login(user=user)

        response = client.post(self.url, data={'csr': self.csr_pem})
        self.assertRequiresLogin(response)

    def test_no_perms(self):
        # User is staff but has no permissions
        client = Client()
        user = User.objects.create_user(username='staff', password='password', email='staff@example.com',
                                        is_staff=True)
        client.force_login(user=user)

        response = client.post(self.url, data={'csr': self.csr_pem})
        self.assertEqual(response.status_code, 403)

    def test_no_staff(self):
        # User isn't staff but has permissions
        client = Client()
        user = User.objects.create_user(username='no_perms', password='password',
                                        email='no_perms@example.com')
        p = Permission.objects.get(codename='change_certificate')
        user.user_permissions.add(p)
        client.force_login(user=user)

        response = client.post(self.url, data={'csr': self.csr_pem})
        self.assertRequiresLogin(response)


class CertDownloadTestCase(AdminTestMixin, DjangoCAWithGeneratedCertsTestCase):
    def setUp(self):
        super(CertDownloadTestCase, self).setUp()
        self.cert = self.certs['root-cert']

    def get_url(self, cert):
        return reverse('admin:django_ca_certificate_download', kwargs={'pk': cert.pk})

    @property
    def url(self):
        return self.get_url(cert=self.cert)

    def test_basic(self):
        filename = 'root-cert_example_com.pem'
        response = self.client.get('%s?format=PEM' % self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/pkix-cert')
        self.assertEqual(response['Content-Disposition'], 'attachment; filename=%s' % filename)
        self.assertEqual(force_text(response.content), self.cert.pub)

    def test_der(self):
        filename = 'root-cert_example_com.der'
        response = self.client.get('%s?format=DER' % self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/pkix-cert')
        self.assertEqual(response['Content-Disposition'], 'attachment; filename=%s' % filename)
        self.assertEqual(response.content, self.cert.dump_certificate(Encoding.DER))

    def test_not_found(self):
        url = reverse('admin:django_ca_certificate_download', kwargs={'pk': '123'})
        response = self.client.get('%s?format=DER' % url)
        self.assertEqual(response.status_code, 404)

    def test_bad_format(self):
        response = self.client.get('%s?format=bad' % self.url)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.content, b'')

    def test_anonymous(self):
        # Try an anonymous download
        client = Client()
        response = client.get('%s?format=PEM' % self.url)
        self.assertRequiresLogin(response)

    def test_plain_user(self):
        # User isn't staff and has no permissions
        client = Client()
        User.objects.create_user(username='plain', password='password', email='user@example.com')
        self.assertTrue(client.login(username='plain', password='password'))
        response = client.get('%s?format=PEM' % self.url)
        self.assertRequiresLogin(response)

    def test_no_perms(self):
        # User is staff but has no permissions
        client = Client()
        user = User.objects.create_user(username='no_perms', password='password', email='user@example.com',
                                        is_staff=True)
        user.save()
        self.assertTrue(client.login(username='no_perms', password='password'))

        response = client.get('%s?format=PEM' % self.url)
        self.assertEqual(response.status_code, 403)

    def test_no_staff(self):
        # User isn't staff but has permissions
        client = Client()
        response = client.get('%s?format=PEM' % self.url)

        # create a user
        user = User.objects.create_user(username='no_perms', password='password', email='user@example.com')
        p = Permission.objects.get(codename='change_certificate')
        user.user_permissions.add(p)
        self.assertTrue(client.login(username='no_perms', password='password'))

        self.assertRequiresLogin(response)


class CertDownloadBundleTestCase(AdminTestMixin, DjangoCAWithGeneratedCertsTestCase):
    def setUp(self):
        super(CertDownloadBundleTestCase, self).setUp()
        self.cert = self.certs['root-cert']

    def get_url(self, cert):
        return reverse('admin:django_ca_certificate_download_bundle', kwargs={'pk': cert.pk})

    @property
    def url(self):
        return self.get_url(cert=self.cert)

    def test_cert(self):
        filename = 'root-cert_example_com_bundle.pem'
        response = self.client.get('%s?format=PEM' % self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/pkix-cert')
        self.assertEqual(response['Content-Disposition'], 'attachment; filename=%s' % filename)
        self.assertEqual(force_text(response.content),
                         '%s\n%s' % (self.cert.pub.strip(), self.cert.ca.pub.strip()))
        self.assertEqual(self.cas['root'], self.cert.ca)  # just to be sure we test the right thing

    def test_invalid_format(self):
        response = self.client.get('%s?format=INVALID' % self.url)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.content, b'')

        # DER is not supported for bundles
        response = self.client.get('%s?format=DER' % self.url)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.content, b'DER/ASN.1 certificates cannot be downloaded as a bundle.')


class ResignCertTestCase(AdminTestMixin, WebTestMixin, DjangoCAWithGeneratedCertsTestCase):
    def setUp(self):
        super(ResignCertTestCase, self).setUp()
        self.cert = self.certs['root-cert']

    def get_url(self, cert):
        return reverse('admin:django_ca_certificate_actions', kwargs={'pk': cert.pk, 'tool': 'resign'})

    @property
    def url(self):
        return self.get_url(cert=self.cert)

    def assertResigned(self, cert=None):
        if cert is None:
            cert = self.cert

        resigned = Certificate.objects.filter(cn=cert.cn).exclude(pk=cert.pk).get()
        self.assertFalse(cert.revoked)

        self.assertEqual(cert.cn, resigned.cn)
        self.assertEqual(cert.csr, resigned.csr)
        self.assertEqual(cert.distinguishedName(), resigned.distinguishedName())
        self.assertEqual(cert.extended_key_usage, resigned.extended_key_usage)
        self.assertEqual(cert.key_usage, resigned.key_usage)
        self.assertEqual(cert.subject_alternative_name, resigned.subject_alternative_name)
        self.assertEqual(cert.tls_feature, resigned.tls_feature)

        # Some properties are obviously *not* equal
        self.assertNotEqual(cert.pub, resigned.pub)
        self.assertNotEqual(cert.serial, resigned.serial)

    @override_tmpcadir()
    def test_get(self):
        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(pre.called)
        self.assertFalse(post.called)

    @override_tmpcadir()
    def test_resign(self):
        cn = 'resigned.example.com'
        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            response = self.client.post(self.url, data={
                'ca': self.cert.ca.pk,
                'profile': 'webserver',
                'subject_5': cn,
                'subject_alternative_name_1': True,
                'algorithm': 'SHA256',
                'expires': self.cert.ca.expires.strftime('%Y-%m-%d'),
                'key_usage_0': ['digitalSignature', 'keyAgreement', ],
                'key_usage_1': True,
                'extended_key_usage_0': ['clientAuth', 'serverAuth', ],
                'extended_key_usage_1': False,
                'tls_feature_0': ['OCSPMustStaple', 'MultipleCertStatusRequest'],
                'tls_feature_1': False,
            })
        self.assertRedirects(response, self.changelist_url)
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(post.call_count, 1)
        self.assertTrue(Certificate.objects.get(cn=cn).cn, cn)

    def test_no_csr(self):
        self.cert.csr = ''
        self.cert.save()

        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            response = self.client.get(self.url)
        self.assertRedirects(response, self.change_url())
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertMessages(response, ['Certificate has no CSR (most likely because it was imported).'])

    @override_tmpcadir()
    def test_webtest_basic(self):
        # resign the basic cert
        form = self.app.get(self.url, user=self.user.username).form
        form.submit().follow()
        self.assertResigned(self.cert)

    @override_tmpcadir()
    def test_webtest_all(self):
        # resign the basic cert
        cert = self.certs['all-extensions']
        form = self.app.get(self.get_url(cert), user=self.user.username).form
        form.submit().follow()
        self.assertResigned(cert)

    @override_tmpcadir()
    def test_webtest_no_ext(self):
        cert = self.certs['no-extensions']
        form = self.app.get(self.get_url(cert), user=self.user.username).form
        form.submit().follow()
        self.assertResigned(cert)


class RevokeCertViewTestCase(AdminTestMixin, DjangoCAWithCertTestCase):
    def setUp(self):
        super(RevokeCertViewTestCase, self).setUp()
        self.cert = self.certs['root-cert']

    def get_url(self, cert):
        return reverse('admin:django_ca_certificate_actions', kwargs={'pk': cert.pk, 'tool': 'revoke_change'})

    @property
    def url(self):
        return self.get_url(cert=self.cert)

    @override_tmpcadir()
    def test_get(self):
        with self.assertSignal(pre_revoke_cert) as pre, self.assertSignal(post_revoke_cert) as post:
            self.client.get(self.url)
        self.assertFalse(pre.called)
        self.assertFalse(post.called)

    def test_no_reason(self):
        with self.assertSignal(pre_revoke_cert) as pre, self.assertSignal(post_revoke_cert) as post:
            response = self.client.post(self.url, data={'revoked_reason': ''})
        self.assertTrue(pre.called)
        self.assertPostRevoke(post, self.cert)
        self.assertRedirects(response, self.change_url())
        self.assertTemplateUsed('django_ca/admin/certificate_revoke_form.html')
        self.assertRevoked(self.cert)

    def test_with_reason(self):
        reason = ReasonFlags.certificate_hold
        with self.assertSignal(pre_revoke_cert) as pre, self.assertSignal(post_revoke_cert) as post:
            response = self.client.post(self.url, data={'revoked_reason': reason.name})
        self.assertTrue(pre.called)
        self.assertPostRevoke(post, self.cert)
        self.assertRedirects(response, self.change_url())
        self.assertTemplateUsed('django_ca/admin/certificate_revoke_form.html')
        self.assertRevoked(self.cert, reason=reason.name)

    def test_with_bogus_reason(self):
        # so the form is not valid

        reason = 'bogus'
        with self.assertSignal(pre_revoke_cert) as pre, self.assertSignal(post_revoke_cert) as post:
            response = self.client.post(self.url, data={'revoked_reason': reason})
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertNotRevoked(self.cert)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed('django_ca/admin/certificate_revoke_form.html')
        self.assertEqual(
            response.context['form'].errors,
            {'revoked_reason': ['Select a valid choice. bogus is not one of the available choices.']})

    def test_revoked(self):
        cert = Certificate.objects.get(serial=self.cert.serial)
        cert.revoke()
        cert.save()

        with self.assertSignal(pre_revoke_cert) as pre, self.assertSignal(post_revoke_cert) as post:
            response = self.client.get(self.url)
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertRedirects(response, self.change_url())

        # Revoke a second time, does not update
        with self.assertSignal(pre_revoke_cert) as pre, self.assertSignal(post_revoke_cert) as post:
            response = self.client.post(self.url, data={'revoked_reason': 'certificateHold'})
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertRedirects(response, self.change_url())
        self.assertRevoked(self.cert)

    def test_anonymous(self):
        client = Client()

        with self.assertSignal(pre_revoke_cert) as pre, self.assertSignal(post_revoke_cert) as post:
            response = client.get(self.url)
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertRequiresLogin(response)
        self.assertNotRevoked(self.cert)

        with self.assertSignal(pre_revoke_cert) as pre, self.assertSignal(post_revoke_cert) as post:
            response = client.post(self.url, data={})
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertRequiresLogin(response)
        self.assertNotRevoked(self.cert)

    def test_plain_user(self):
        # User isn't staff and has no permissions
        client = Client()
        User.objects.create_user(username='plain', password='password', email='plain@example.com')
        self.assertTrue(client.login(username='plain', password='password'))

        with self.assertSignal(pre_revoke_cert) as pre, self.assertSignal(post_revoke_cert) as post:
            response = client.get(self.url)
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertRequiresLogin(response)
        self.assertNotRevoked(self.cert)

        with self.assertSignal(pre_revoke_cert) as pre, self.assertSignal(post_revoke_cert) as post:
            response = client.post(self.url, data={})
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertRequiresLogin(response)
        self.assertNotRevoked(self.cert)

    def test_no_perms(self):
        # User is staff but has no permissions
        client = Client()
        user = User.objects.create_user(username='staff', password='password', email='staff@example.com',
                                        is_staff=True)
        user.save()
        self.assertTrue(client.login(username='staff', password='password'))

        with self.assertSignal(pre_revoke_cert) as pre, self.assertSignal(post_revoke_cert) as post:
            response = client.get(self.url)
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertEqual(response.status_code, 403)
        self.assertNotRevoked(self.cert)

        with self.assertSignal(pre_revoke_cert) as pre, self.assertSignal(post_revoke_cert) as post:
            response = client.post(self.url, data={})
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertEqual(response.status_code, 403)
        self.assertNotRevoked(self.cert)

    def test_no_staff(self):
        # User isn't staff but has permissions
        client = Client()
        user = User.objects.create_user(username='no_perms', password='password',
                                        email='no_perms@example.com')
        p = Permission.objects.get(codename='change_certificate')
        user.user_permissions.add(p)
        self.assertTrue(client.login(username='no_perms', password='password'))

        with self.assertSignal(pre_revoke_cert) as pre, self.assertSignal(post_revoke_cert) as post:
            response = client.get(self.url)
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertRequiresLogin(response)

        with self.assertSignal(pre_revoke_cert) as pre, self.assertSignal(post_revoke_cert) as post:
            response = client.post(self.url, data={})
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertRequiresLogin(response)
        self.assertNotRevoked(self.cert)


class ProfileSelectionTests(AdminTestMixin, SeleniumTestCase):
    def test_no_add(self):
        pass

    @override_tmpcadir()
    def test_select(self):
        self.load_usable_cas()
        self.create_superuser()
        self.login()

        self.selenium.get('%s%s' % (self.live_server_url, self.add_url))
        select = self.find('select#id_profile')
        for option in select.find_elements_by_tag_name("option"):
            #print("Value is: %s" % option.get_attribute("value"))
            option.click()
