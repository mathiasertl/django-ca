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

"""Base test cases for admin views and CertificateAdmin tests."""

import json
from http import HTTPStatus
from unittest import mock

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.extensions import Extension
from cryptography.x509.extensions import UnrecognizedExtension
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.oid import ObjectIdentifier

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import Client
from django.urls import reverse
from django.utils.encoding import force_str

from django_webtest import WebTestMixin
from freezegun import freeze_time

from .. import ca_settings
from .. import extensions
from .. import models
from ..constants import ReasonFlags
from ..models import Certificate
from ..models import Watcher
from ..signals import post_issue_cert
from ..signals import post_revoke_cert
from ..signals import pre_issue_cert
from ..signals import pre_revoke_cert
from ..subject import Subject
from ..utils import SUBJECT_FIELDS
from .base import DjangoCATestCase
from .base import DjangoCAWithCertTestCase
from .base import DjangoCAWithGeneratedCertsTestCase
from .base import certs
from .base import override_settings
from .base import override_tmpcadir
from .base import timestamps
from .base_mixins import AdminTestCaseMixin

User = get_user_model()


class StandardAdminViewTestMixin(AdminTestCaseMixin):
    """A mixin that adds tests for the standard Django admin views.

    TestCases using this mixin are expected to implement ``setUp`` to add some useful test model instances.
    """

    def test_model_count(self):
        """Test that the implementing TestCase actually creates some instances."""
        self.assertGreater(self.model.objects.all().count(), 0)

    def test_changelist_view(self):
        """Test that the changelist view works."""
        response = self.client.get(self.changelist_url)
        self.assertChangelistResponse(response, *self.model.objects.all())

    def test_change_view(self):
        """Test that the change view works for all instances."""
        for obj in self.model.objects.all():
            response = self.client.get(obj.admin_change_url)
            self.assertChangeResponse(response)


class CertificateAdminTestCaseMixin(AdminTestCaseMixin):
    """Specialized variant of :py:class:`~django_ca.tests.tests_admin.AdminTestCaseMixin` for certificates."""

    model = Certificate

    def change_url(self, cert=None):
        """Shortcut to be able to get admin_change_url from root-cert by default."""
        if cert is None:
            cert = self.certs['root-cert']
        return cert.admin_change_url

    def assertChangeResponse(self, response):
        """Overwritten here to make sure custom templates are loaded."""
        super().assertChangeResponse(response)

        templates = [t.name for t in response.templates]
        self.assertIn('admin/django_ca/certificate/change_form.html', templates)
        self.assertCSS(response, 'django_ca/admin/css/base.css')
        self.assertCSS(response, 'django_ca/admin/css/certificateadmin.css')


@freeze_time(timestamps['everything_valid'])
class ChangelistTestCase(CertificateAdminTestCaseMixin, DjangoCAWithGeneratedCertsTestCase):
    """Test the changelist view."""

    def assertResponse(self, response, certs=None):
        if certs is None:
            certs = []

        self.assertEqual(response.status_code, 200)
        self.assertCSS(response, 'django_ca/admin/css/base.css')
        self.assertCSS(response, 'django_ca/admin/css/certificateadmin.css')
        self.assertEqual(set(response.context['cl'].result_list), set(certs))

    def test_get(self):
        """Test a normal get response."""
        response = self.client.get(self.changelist_url)
        self.assertResponse(response, self.certs.values())

    def test_status_all(self):
        """Test various status filters."""
        # Test viewing all certificates, regardless of revocation or current time
        self.load_all_certs()  # load all certs here

        response = self.client.get('%s?status=all' % self.changelist_url)
        self.assertResponse(response, self.certs.values())

        # Revoke everything and try again
        for cert in self.certs.values():
            cert.revoke()
            cert.save()
        response = self.client.get('%s?status=all' % self.changelist_url)
        self.assertResponse(response, self.certs.values())

        with self.freeze_time('everything_expired'):
            response = self.client.get('%s?status=all' % self.changelist_url)
            self.assertResponse(response, self.certs.values())

        with self.freeze_time('before_everything'):
            response = self.client.get('%s?status=all' % self.changelist_url)
            self.assertResponse(response, self.certs.values())

        # Revoke everything and try again
        with self.freeze_time('everything_valid'):
            for cert in self.certs.values():
                cert.revoke()
                cert.save()
            response = self.client.get('%s?status=all' % self.changelist_url)
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

        response = self.client.get(self.changelist_url)
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

        response = self.client.get(self.changelist_url)
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

        response = self.client.get(self.changelist_url)
        self.assertResponse(response, valid)
        response = self.client.get('%s?status=expired' % self.changelist_url)
        self.assertResponse(response, [])
        response = self.client.get('%s?status=revoked' % self.changelist_url)
        self.assertResponse(response, [self.certs['root-cert']])

    @freeze_time(timestamps['everything_valid'])
    def test_autogenerated(self):
        self.certs['root-cert'].autogenerated = True
        self.certs['root-cert'].save()

        non_auto = [c for c in self.certs.values() if c != self.certs['root-cert']]
        response = self.client.get(self.changelist_url)
        self.assertResponse(response, non_auto)
        response = self.client.get('%s?auto=auto' % self.changelist_url)
        self.assertResponse(response, [self.certs['root-cert']])
        response = self.client.get('%s?auto=all' % self.changelist_url)
        self.assertResponse(response, self.certs.values())

    def test_unauthorized(self):
        client = Client()
        response = client.get(self.changelist_url)
        self.assertRequiresLogin(response)


@override_settings(USE_TZ=True)
class ChangelistWithTZTestCase(ChangelistTestCase):
    pass


# NOTE: default view gives only valid certificates, so an expired would not be included by default
@freeze_time(timestamps['everything_valid'])
class RevokeActionTestCase(CertificateAdminTestCaseMixin, DjangoCAWithGeneratedCertsTestCase):
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
        self.assertEqual(cert.revoked_reason, '')

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


class ChangeTestCase(CertificateAdminTestCaseMixin, DjangoCAWithCertTestCase):
    def test_basic(self):
        # Just assert that viewing a certificate does not throw an exception
        for name, cert in self.certs.items():
            response = self.client.get(cert.admin_change_url)
            self.assertChangeResponse(response)

    def test_revoked(self):
        # view a revoked certificate (fieldsets are collapsed differently)
        self.certs['root-cert'].revoke()

        response = self.client.get(self.change_url())
        self.assertChangeResponse(response)

        self.assertContains(response, text='''<div class="fieldBox field-revoked"><label>Revoked:</label>
                     <div class="readonly"><img src="/static/admin/img/icon-yes.svg" alt="True"></div>
                </div>''', html=True)

    def test_no_san(self):
        # Test display of a certificate with no SAN
        cert = self.certs['no-extensions']
        response = self.client.get(cert.admin_change_url)
        self.assertChangeResponse(response)
        self.assertContains(response, text='''
<div class="form-row field-subject_alternative_name">
    <div>
        <label>SubjectAlternativeName:</label>
        <div class="readonly">
            <span class="django-ca-extension">
                <div class="django-ca-extension-value">
                    &lt;Not present&gt;
                </div>
            </span>
        </div>
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
        cert = self.certs['all-extensions']
        # Act as if no extensions is recognized, to see what happens if we'd encounter an unknown extension.
        with mock.patch.object(models, 'OID_TO_EXTENSION', {}), \
                mock.patch.object(extensions, 'OID_TO_EXTENSION', {}), \
                self.assertLogs() as logs:
            response = self.client.get(cert.admin_change_url)
            self.assertChangeResponse(response)

        log_msg = 'WARNING:django_ca.models:Unknown extension encountered: %s'
        expected = [
            log_msg % 'AuthorityInfoAccess (1.3.6.1.5.5.7.1.1)',
            log_msg % 'AuthorityKeyIdentifier (2.5.29.35)',
            log_msg % 'BasicConstraints (2.5.29.19)',
            log_msg % 'CRLDistributionPoints (2.5.29.31)',
            log_msg % 'CtPoison (1.3.6.1.4.1.11129.2.4.3)',
            log_msg % 'ExtendedKeyUsage (2.5.29.37)',
            log_msg % 'FreshestCRL (2.5.29.46)',
            log_msg % 'InhibitAnyPolicy (2.5.29.54)',
            log_msg % 'IssuerAltName (2.5.29.18)',
            log_msg % 'KeyUsage (2.5.29.15)',
            log_msg % 'NameConstraints (2.5.29.30)',
            log_msg % 'OCSPNoCheck (1.3.6.1.5.5.7.48.1.5)',
            log_msg % 'PolicyConstraints (2.5.29.36)',
            log_msg % 'SubjectAltName (2.5.29.17)',
            log_msg % 'SubjectKeyIdentifier (2.5.29.14)',
            log_msg % 'TLSFeature (1.3.6.1.5.5.7.1.24)',
        ]

        self.assertEqual(logs.output, sorted(expected))

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
            response = self.client.get(cert.admin_change_url)
            self.assertChangeResponse(response)

    def test_unknown_object(self):
        response = self.client.get(self.change_url(Certificate(pk=1234)))
        self.assertEqual(response.status_code, 302)


class CSRDetailTestCase(CertificateAdminTestCaseMixin, DjangoCATestCase):
    def setUp(self):
        self.url = reverse('admin:django_ca_certificate_csr_details')
        self.csr_pem = certs['root-cert']['csr']['pem']
        super(CSRDetailTestCase, self).setUp()

    def test_basic(self):
        for name, cert_data in [(k, v) for k, v in certs.items()
                                if v['type'] == 'cert' and v['cat'] == 'generated']:
            response = self.client.post(self.url, data={'csr': cert_data['csr']['pem']})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(json.loads(response.content.decode('utf-8')),
                             {'subject': cert_data['csr_subject']})

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


class ProfilesViewTestCase(CertificateAdminTestCaseMixin, DjangoCATestCase):
    def setUp(self):
        self.url = reverse('admin:django_ca_certificate_profiles')
        super(ProfilesViewTestCase, self).setUp()

    def test_basic(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content.decode('utf-8')), {
            'client': {
                'cn_in_san': True,
                'description': 'A certificate for a client.',
                'extensions': {
                    'basic_constraints': {
                        'critical': True,
                        'value': {'ca': False},
                    },
                    'key_usage': {
                        'critical': True,
                        'value': ['digitalSignature'],
                    },
                    'extended_key_usage': {
                        'critical': False,
                        'value': ['clientAuth'],
                    },
                },
                'subject': dict(Subject(ca_settings.CA_DEFAULT_SUBJECT)),
            },
            'enduser': {
                'cn_in_san': False,
                'description':
                    'A certificate for an enduser, allows client authentication, code and email signing.',
                'extensions': {
                    'basic_constraints': {
                        'critical': True,
                        'value': {'ca': False},
                    },
                    'key_usage': {
                        'critical': True,
                        'value': ['dataEncipherment', 'digitalSignature', 'keyEncipherment', ],
                    },
                    'extended_key_usage': {
                        'critical': False,
                        'value': ['clientAuth', 'codeSigning', 'emailProtection'],
                    },
                },
                'subject': dict(Subject(ca_settings.CA_DEFAULT_SUBJECT)),
            },
            'ocsp': {
                'cn_in_san': False,
                'description': 'A certificate for an OCSP responder.',
                'extensions': {
                    'basic_constraints': {
                        'critical': True,
                        'value': {'ca': False},
                    },
                    'key_usage': {
                        'critical': True,
                        'value': ['digitalSignature', 'keyEncipherment', 'nonRepudiation'],
                    },
                    'extended_key_usage': {
                        'critical': False,
                        'value': ['OCSPSigning'],
                    },
                },
                'subject': dict(Subject(ca_settings.CA_DEFAULT_SUBJECT)),
            },
            'server': {
                'cn_in_san': True,
                'description': 'A certificate for a server, allows client and server authentication.',
                'extensions': {
                    'basic_constraints': {
                        'critical': True,
                        'value': {'ca': False},
                    },
                    'key_usage': {
                        'critical': True,
                        'value': ['digitalSignature', 'keyAgreement', 'keyEncipherment', ],
                    },
                    'extended_key_usage': {
                        'critical': False,
                        'value': ['clientAuth', 'serverAuth'],
                    },
                },
                'subject': dict(Subject(ca_settings.CA_DEFAULT_SUBJECT)),
            },
            'webserver': {
                'cn_in_san': True,
                'description': 'A certificate for a webserver.',
                'extensions': {
                    'basic_constraints': {
                        'critical': True,
                        'value': {'ca': False},
                    },
                    'key_usage': {
                        'critical': True,
                        'value': ['digitalSignature', 'keyAgreement', 'keyEncipherment', ],
                    },
                    'extended_key_usage': {
                        'critical': False,
                        'value': ['serverAuth'],
                    },
                },
                'subject': dict(Subject(ca_settings.CA_DEFAULT_SUBJECT)),
            },
        })

    def test_permission_denied(self):
        client = Client()
        user = User.objects.create_user(username='staff', password='password', email='staff@example.com',
                                        is_staff=True)
        client.force_login(user=user)

        response = client.get(self.url)
        self.assertEqual(response.status_code, 403)

    # removes all profiles, adds one pretty boring one
    @override_tmpcadir(CA_PROFILES={
        'webserver': None,
        'server': None,
        'ocsp': None,
        'enduser': None,
        'client': None,
        'test': {
            'cn_in_san': True,
        }
    })
    def test_empty_profile(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content.decode('utf-8')), {
            'test': {
                'cn_in_san': True,
                'description': '',
                'extensions': {
                    'basic_constraints': {
                        'critical': True,
                        'value': {'ca': False},
                    },
                },
                'subject': dict(Subject(ca_settings.CA_DEFAULT_SUBJECT)),
            },
        })


class CertDownloadTestCase(CertificateAdminTestCaseMixin, DjangoCAWithGeneratedCertsTestCase):
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
        self.assertEqual(force_str(response.content), self.cert.pub)

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


class CertDownloadBundleTestCase(CertificateAdminTestCaseMixin, DjangoCAWithGeneratedCertsTestCase):
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
        self.assertEqual(force_str(response.content),
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


@freeze_time(timestamps['everything_valid'])
class ResignCertTestCase(CertificateAdminTestCaseMixin, WebTestMixin, DjangoCAWithGeneratedCertsTestCase):
    def setUp(self):
        super(ResignCertTestCase, self).setUp()
        self.cert = self.certs['root-cert']
        self.cert.profile = 'webserver'
        self.cert.save()

    def get_url(self, cert):
        return reverse('admin:django_ca_certificate_actions', kwargs={'pk': cert.pk, 'tool': 'resign'})

    @property
    def url(self):
        return self.get_url(cert=self.cert)

    def assertResigned(self, cert=None, resigned=None, expected_cn=None):
        if cert is None:
            cert = self.cert
        if resigned is None:
            resigned = Certificate.objects.filter(cn=cert.cn).exclude(pk=cert.pk).get()
        if expected_cn is None:
            expected_cn = cert.cn
        self.assertFalse(cert.revoked)

        self.assertEqual(resigned.cn, expected_cn)
        self.assertEqual(cert.csr, resigned.csr)
        self.assertEqual(cert.profile, resigned.profile)
        self.assertEqual(cert.distinguished_name, resigned.distinguished_name)
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
        """Try a basic resign request."""
        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            response = self.client.post(self.url, data={
                'ca': self.cert.ca.pk,
                'profile': 'webserver',
                'subject_5': self.cert.cn,
                'subject_alternative_name_1': True,
                'algorithm': 'SHA256',
                'expires': self.cert.ca.expires.strftime('%Y-%m-%d'),
                'key_usage_0': ['digitalSignature', 'keyAgreement', 'keyEncipherment'],
                'key_usage_1': True,
                'extended_key_usage_0': ['clientAuth', 'serverAuth', ],
                'extended_key_usage_1': False,
                'tls_feature_0': [],
                'tls_feature_1': False,
            })
        self.assertRedirects(response, self.changelist_url)
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(post.call_count, 1)
        self.assertResigned()

    @override_tmpcadir()  # otherwise there are no usable CAs, hiding the message we want to test
    def test_no_permission(self):
        """Try resigning a certificate when we don't have the permissions."""
        self.user.is_superuser = False
        self.user.save()

        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            response = self.client.get(self.url)
        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)
        self.assertFalse(pre.called)
        self.assertFalse(post.called)

    @override_tmpcadir()  # otherwise there are no usable CAs, hiding the message we want to test
    def test_no_csr(self):
        """Try resigning a cert that has no CSR."""
        self.cert.csr = ''
        self.cert.save()

        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            response = self.client.get(self.url)
        self.assertRedirects(response, self.change_url())
        self.assertFalse(pre.called)
        self.assertFalse(post.called)
        self.assertMessages(response, ['Certificate has no CSR (most likely because it was imported).'])

    @override_tmpcadir()
    def test_no_profile(self):
        """Test that resigning a cert with no stored profile stores the default profile."""

        self.cert.profile = ''
        self.cert.save()
        form = self.app.get(self.url, user=self.user.username).form
        form.submit().follow()

        resigned = Certificate.objects.filter(cn=self.cert.cn).exclude(pk=self.cert.pk).get()
        self.assertEqual(resigned.profile, ca_settings.CA_DEFAULT_PROFILE)

    @override_tmpcadir()
    def test_webtest_basic(self):
        """Resign basic certificate."""
        form = self.app.get(self.url, user=self.user.username).form
        form.submit().follow()
        self.assertResigned(self.cert)

    @override_tmpcadir()
    def test_webtest_all(self):
        """Resign certificate with **all** extensions."""
        cert = self.certs['all-extensions']
        cert.profile = 'webserver'
        cert.save()
        form = self.app.get(self.get_url(cert), user=self.user.username).form
        form.submit().follow()
        self.assertResigned(cert)

    @override_tmpcadir(CA_DEFAULT_SUBJECT={})
    def test_webtest_no_ext(self):
        """Resign certificate with **no** extensions."""
        cert = self.certs['no-extensions']
        cert.profile = 'webserver'
        cert.save()
        form = self.app.get(self.get_url(cert), user=self.user.username).form
        form.submit().follow()
        self.assertResigned(cert)


class RevokeCertViewTestCase(CertificateAdminTestCaseMixin, DjangoCAWithCertTestCase):
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
        self.assertTemplateUsed('admin/django_ca/certificate/revoke_form.html')
        self.assertRevoked(self.cert)

    def test_with_reason(self):
        reason = ReasonFlags.certificate_hold
        with self.assertSignal(pre_revoke_cert) as pre, self.assertSignal(post_revoke_cert) as post:
            response = self.client.post(self.url, data={'revoked_reason': reason.name})
        self.assertTrue(pre.called)
        self.assertPostRevoke(post, self.cert)
        self.assertRedirects(response, self.change_url())
        self.assertTemplateUsed('admin/django_ca/certificate/revoke_form.html')
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
        self.assertTemplateUsed('admin/django_ca/certificate/revoke_form.html')
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
