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
from datetime import datetime
from datetime import timedelta
from urllib.parse import quote

from cryptography.hazmat.primitives.serialization import Encoding

from django.contrib.auth.models import User
from django.contrib.auth.models import Permission
from django.contrib.staticfiles.templatetags.staticfiles import static
from django.test import Client
from django.utils import timezone
from django.utils.encoding import force_text

from ..models import Certificate
from ..models import CertificateAuthority
from ..utils import SUBJECT_FIELDS
from .base import DjangoCAWithCertTestCase
from .base import DjangoCAWithCSRTestCase
from .base import override_tmpcadir

try:
    from django.urls import reverse
except ImportError:  # Django 1.8 import
    from django.core.urlresolvers import reverse


class AdminTestMixin(object):
    def setUp(self):
        self.user = User.objects.create_superuser(username='user', password='password',
                                                  email='user@example.com')
        self.add_url = reverse('admin:django_ca_certificate_add')
        self.changelist_url = reverse('admin:django_ca_certificate_changelist')
        self.client = Client()
        self.assertTrue(self.client.login(username='user', password='password'))
        super(AdminTestMixin, self).setUp()

    def assertCSS(self, response, path):
        css = '<link href="%s" type="text/css" media="all" rel="stylesheet" />' % static(path)
        self.assertInHTML(css, response.content.decode('utf-8'), 1)

    def change_url(self, pk=None):
        if pk is None:
            pk = self.cert.pk

        return reverse('admin:django_ca_certificate_change', args=(pk, ))

    def assertRequiresLogin(self, response, **kwargs):
        expected = '%s?next=%s' % (reverse('admin:login'), quote(response.wsgi_request.get_full_path()))
        self.assertRedirects(response, expected, **kwargs)


class ChangelistTestCase(AdminTestMixin, DjangoCAWithCertTestCase):
    """Test the changelist view."""

    def assertCerts(self, response, certs):
        self.assertEqual(set(response.context['cl'].result_list), set(certs))

    def test_get(self):
        response = self.client.get(self.changelist_url)
        self.assertEqual(response.status_code, 200)
        self.assertCerts(response, [self.cert])

        self.assertCSS(response, 'django_ca/admin/css/monospace.css')
        self.assertCSS(response, 'django_ca/admin/css/certificateadmin.css')

    def test_status(self):
        response = self.client.get('%s?status=valid' % self.changelist_url)
        self.assertEqual(response.status_code, 200)
        self.assertCerts(response, [self.cert])
        response = self.client.get('%s?status=expired' % self.changelist_url)
        self.assertCerts(response, [])
        self.assertEqual(response.status_code, 200)
        response = self.client.get('%s?status=revoked' % self.changelist_url)
        self.assertEqual(response.status_code, 200)
        self.assertCerts(response, [])

        # get the cert and manipulate it so that it shows up in the changelist:
        cert = Certificate.objects.get(serial=self.cert.serial)
        cert.expires = timezone.now() - timedelta(days=1)
        cert.save()

        response = self.client.get('%s?status=expired' % self.changelist_url)
        self.assertCerts(response, [self.cert])
        self.assertEqual(response.status_code, 200)

        cert.revoke()
        response = self.client.get('%s?status=revoked' % self.changelist_url)
        self.assertEqual(response.status_code, 200)
        self.assertCerts(response, [self.cert])

    def test_unauthorized(self):
        client = Client()
        response = client.get(self.changelist_url)
        self.assertRequiresLogin(response)


class RevokeActionTestCase(AdminTestMixin, DjangoCAWithCertTestCase):
    """Test the "revoke" action in the changelist."""

    def test_basic(self):
        self.assertNotRevoked(self.cert)

        data = {
            'action': 'revoke', '_selected_action': [self.cert.pk],
        }
        response = self.client.post(self.changelist_url, data)
        self.assertRedirects(response, self.changelist_url)
        self.assertRevoked(self.cert)

        # revoking revoked certs does nothing:
        response = self.client.post(self.changelist_url, data)
        self.assertRedirects(response, self.changelist_url)
        self.assertRevoked(self.cert)

    def test_permissions(self):
        data = {
            'action': 'revoke', '_selected_action': [self.cert.pk],
        }

        # make an anonymous request
        client = Client()
        response = client.post(self.changelist_url, data)
        self.assertRequiresLogin(response)

        # cert is not revoked
        cert = Certificate.objects.get(serial=self.cert.serial)
        self.assertFalse(cert.revoked)
        self.assertIsNone(cert.revoked_reason)

        # test with a logged in user, but not staff
        user = User.objects.create_user(username='staff', password='password', email='staff@example.com')
        self.assertTrue(client.login(username='staff', password='password'))

        response = client.post(self.changelist_url, data)
        self.assertRequiresLogin(response)
        self.assertNotRevoked(self.cert)

        # make the user "staff"
        user.is_staff = True
        user.save()
        self.assertTrue(User.objects.get(username='staff').is_staff)  # really is staff, right?
        response = client.post(self.changelist_url, data)
        self.assertEqual(response.status_code, 403)
        self.assertNotRevoked(self.cert)

        # now give appropriate permission
        p = Permission.objects.get(codename='change_certificate')
        user.user_permissions.add(p)
        response = client.post(self.changelist_url, data)
        self.assertRevoked(self.cert)


class ChangeTestCase(AdminTestMixin, DjangoCAWithCertTestCase):
    def test_basic(self):
        response = self.client.get(self.change_url())
        self.assertEqual(response.status_code, 200)

        templates = [t.name for t in response.templates]
        self.assertIn('django_ca/admin/change_form.html', templates)
        self.assertIn('admin/change_form.html', templates)
        self.assertCSS(response, 'django_ca/admin/css/monospace.css')
        self.assertCSS(response, 'django_ca/admin/css/certificateadmin.css')

    def test_revoked(self):
        # view a revoked certificate (fieldsets are collapsed differently)
        cert = Certificate.objects.get(serial=self.cert.serial)
        cert.revoke()

        response = self.client.get(self.change_url())
        self.assertEqual(response.status_code, 200)

        templates = [t.name for t in response.templates]
        self.assertIn('django_ca/admin/change_form.html', templates)
        self.assertIn('admin/change_form.html', templates)
        self.assertCSS(response, 'django_ca/admin/css/monospace.css')
        self.assertCSS(response, 'django_ca/admin/css/certificateadmin.css')


class AddTestCase(AdminTestMixin, DjangoCAWithCSRTestCase):
    def test_get(self):
        response = self.client.get(self.add_url)
        self.assertEqual(response.status_code, 200)
        templates = [t.name for t in response.templates]
        self.assertIn('django_ca/admin/change_form.html', templates)
        self.assertIn('admin/change_form.html', templates)
        self.assertCSS(response, 'django_ca/admin/css/monospace.css')
        self.assertCSS(response, 'django_ca/admin/css/certificateadmin.css')

    def test_add(self):
        cn = 'test-add.example.com'
        response = self.client.post(self.add_url, data={
            'csr': self.csr_pem,
            'ca': self.ca.pk,
            'profile': 'webserver',
            'subject_0': 'US',
            'subject_5': cn,
            'subjectAltName_1': True,
            'algorithm': 'SHA256',
            'expires': self.ca.expires.strftime('%Y-%m-%d'),
            'keyUsage_0': ['digitalSignature', 'keyAgreement', ],
            'keyUsage_1': True,
            'extendedKeyUsage_0': ['clientAuth', 'serverAuth', ],
            'extendedKeyUsage_1': False,
        })
        self.assertRedirects(response, self.changelist_url)

        cert = Certificate.objects.get(cn=cn)
        self.assertSubject(cert.x509, {'C': 'US', 'CN': cn})
        self.assertIssuer(self.ca, cert)
        self.assertAuthorityKeyIdentifier(self.ca, cert)
        self.assertEqual(cert.subjectAltName(), 'DNS:%s' % cn)
        self.assertEqual(cert.basicConstraints(), 'critical,CA:FALSE')
        self.assertEqual(cert.keyUsage(), 'critical,digitalSignature,keyAgreement')
        self.assertEqual(cert.extendedKeyUsage(), 'clientAuth,serverAuth')
        self.assertEqual(cert.ca, self.ca)
        self.assertEqual(cert.csr, self.csr_pem)

    def test_add_no_key_usage(self):
        cn = 'test-add2.example.com'
        san = 'test-san.example.com'
        response = self.client.post(self.add_url, data={
            'csr': self.csr_pem,
            'ca': self.ca.pk,
            'profile': 'webserver',
            'subject_0': 'US',
            'subject_5': cn,
            'subjectAltName_0': san,
            'subjectAltName_1': True,
            'algorithm': 'SHA256',
            'expires': self.ca.expires.strftime('%Y-%m-%d'),
            'keyUsage_0': [],
            'keyUsage_1': False,
            'extendedKeyUsage_0': [],
            'extendedKeyUsage_1': False,
        })
        self.assertRedirects(response, self.changelist_url)

        cert = Certificate.objects.get(cn=cn)
        self.assertSubject(cert.x509, {'C': 'US', 'CN': cn})
        self.assertIssuer(self.ca, cert)
        self.assertAuthorityKeyIdentifier(self.ca, cert)
        self.assertEqual(cert.subjectAltName(), 'DNS:%s, DNS:%s' % (cn, san))
        self.assertEqual(cert.basicConstraints(), 'critical,CA:FALSE')
        self.assertEqual(cert.keyUsage(), '')
        self.assertEqual(cert.extendedKeyUsage(), '')
        self.assertEqual(cert.ca, self.ca)
        self.assertEqual(cert.csr, self.csr_pem)

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_add_with_password(self):
        password = b'foobar'
        name = 'ca_with_pass'
        cn = 'example.com'
        self.cmd('init_ca', name, cn, password=password)
        ca = CertificateAuthority.objects.get(name=name)

        # first post without password
        response = self.client.post(self.add_url, data={
            'csr': self.csr_pem,
            'ca': ca.pk,
            'profile': 'webserver',
            'subject_0': 'US',
            'subject_5': cn,
            'subjectAltName_1': True,
            'algorithm': 'SHA256',
            'expires': self.ca.expires.strftime('%Y-%m-%d'),
            'keyUsage_0': ['digitalSignature', 'keyAgreement', ],
            'keyUsage_1': True,
            'extendedKeyUsage_0': ['clientAuth', 'serverAuth', ],
            'extendedKeyUsage_1': False,
        })
        self.assertFalse(response.context['adminform'].form.is_valid())
        self.assertEqual(response.context['adminform'].form.errors,
                         {'password': ['Password was not given but private key is encrypted']})

        # now post with a false password
        response = self.client.post(self.add_url, data={
            'csr': self.csr_pem,
            'ca': ca.pk,
            'profile': 'webserver',
            'subject_0': 'US',
            'subject_5': cn,
            'subjectAltName_1': True,
            'algorithm': 'SHA256',
            'expires': self.ca.expires.strftime('%Y-%m-%d'),
            'keyUsage_0': ['digitalSignature', 'keyAgreement', ],
            'keyUsage_1': True,
            'extendedKeyUsage_0': ['clientAuth', 'serverAuth', ],
            'extendedKeyUsage_1': False,
            'password': b'wrong',
        })
        self.assertFalse(response.context['adminform'].form.is_valid())
        self.assertEqual(response.context['adminform'].form.errors,
                         {'password': ['Bad decrypt. Incorrect password?']})

        # post with correct password!
        response = self.client.post(self.add_url, data={
            'csr': self.csr_pem,
            'ca': ca.pk,
            'profile': 'webserver',
            'subject_0': 'US',
            'subject_5': cn,
            'subjectAltName_1': True,
            'algorithm': 'SHA256',
            'expires': self.ca.expires.strftime('%Y-%m-%d'),
            'keyUsage_0': ['digitalSignature', 'keyAgreement', ],
            'keyUsage_1': True,
            'extendedKeyUsage_0': ['clientAuth', 'serverAuth', ],
            'extendedKeyUsage_1': False,
            'password': 'foobar',
        })
        self.assertRedirects(response, self.changelist_url)

        cert = Certificate.objects.get(cn=cn)
        self.assertSubject(cert.x509, {'C': 'US', 'CN': cn})
        self.assertIssuer(ca, cert)
        self.assertAuthorityKeyIdentifier(ca, cert)
        self.assertEqual(cert.subjectAltName(), 'DNS:%s' % cn)
        self.assertEqual(cert.basicConstraints(), 'critical,CA:FALSE')
        self.assertEqual(cert.keyUsage(), 'critical,digitalSignature,keyAgreement')
        self.assertEqual(cert.extendedKeyUsage(), 'clientAuth,serverAuth')
        self.assertEqual(cert.ca, ca)
        self.assertEqual(cert.csr, self.csr_pem)

    def test_wrong_csr(self):
        cn = 'test-add-wrong-csr.example.com'
        response = self.client.post(self.add_url, data={
            'csr': 'whatever\n%s' % self.csr_pem,
            'ca': self.ca.pk,
            'profile': 'webserver',
            'subject_0': 'US',
            'subject_5': cn,
            'subjectAltName_1': True,
            'algorithm': 'SHA256',
            'expires': self.ca.expires.strftime('%Y-%m-%d'),
            'keyUsage_0': ['digitalSignature', 'keyAgreement', ],
            'keyUsage_1': True,
            'extendedKeyUsage_0': ['clientAuth', 'serverAuth', ],
            'extendedKeyUsage_1': False,
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn("Enter a valid CSR (in PEM format).", response.content.decode('utf-8'))
        self.assertFalse(response.context['adminform'].form.is_valid())
        self.assertEqual(response.context['adminform'].form.errors,
                         {'csr': ['Enter a valid CSR (in PEM format).']})

        with self.assertRaises(Certificate.DoesNotExist):
            Certificate.objects.get(cn=cn)

    def test_wrong_algorithm(self):
        cn = 'test-add-wrong-algo.example.com'
        response = self.client.post(self.add_url, data={
            'csr': self.csr_pem,
            'ca': self.ca.pk,
            'profile': 'webserver',
            'subject_0': 'US',
            'subject_5': cn,
            'subjectAltName_1': True,
            'algorithm': 'wrong algo',
            'expires': self.ca.expires.strftime('%Y-%m-%d'),
            'keyUsage_0': ['digitalSignature', 'keyAgreement', ],
            'keyUsage_1': True,
            'extendedKeyUsage_0': ['clientAuth', 'serverAuth', ],
            'extendedKeyUsage_1': False,
        })
        self.assertEqual(response.status_code, 200)

        self.assertFalse(response.context['adminform'].form.is_valid())
        self.assertEqual(
            response.context['adminform'].form.errors,
            {'algorithm': ['Select a valid choice. wrong algo is not one of the available choices.']})

    def test_expires_in_the_past(self):
        cn = 'test-expires-in-the-past.example.com'
        expires = datetime.now() - timedelta(days=3)
        response = self.client.post(self.add_url, data={
            'csr': self.csr_pem,
            'ca': self.ca.pk,
            'profile': 'webserver',
            'subject_0': 'US',
            'subject_5': cn,
            'subjectAltName_1': True,
            'algorithm': 'SHA256',
            'expires': expires.strftime('%Y-%m-%d'),
            'keyUsage_0': ['digitalSignature', 'keyAgreement', ],
            'keyUsage_1': True,
            'extendedKeyUsage_0': ['clientAuth', 'serverAuth', ],
            'extendedKeyUsage_1': False,
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn('Certificate cannot expire in the past.', response.content.decode('utf-8'))
        self.assertFalse(response.context['adminform'].form.is_valid())
        self.assertEqual(response.context['adminform'].form.errors,
                         {'expires': ['Certificate cannot expire in the past.']})

        with self.assertRaises(Certificate.DoesNotExist):
            Certificate.objects.get(cn=cn)

    def test_expires_too_late(self):
        cn = 'test-expires-in-the-past.example.com'
        expires = self.ca.expires + timedelta(days=3)
        correct_expires = self.ca.expires.strftime('%Y-%m-%d')
        error = 'CA expires on %s, certificate must not expire after that.' % correct_expires

        response = self.client.post(self.add_url, data={
            'csr': self.csr_pem,
            'ca': self.ca.pk,
            'profile': 'webserver',
            'subject_0': 'US',
            'subject_5': cn,
            'subjectAltName_1': True,
            'algorithm': 'SHA256',
            'expires': expires.strftime('%Y-%m-%d'),
            'keyUsage_0': ['digitalSignature', 'keyAgreement', ],
            'keyUsage_1': True,
            'extendedKeyUsage_0': ['clientAuth', 'serverAuth', ],
            'extendedKeyUsage_1': False,
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(error, response.content.decode('utf-8'))
        self.assertFalse(response.context['adminform'].form.is_valid())
        self.assertEqual(response.context['adminform'].form.errors, {'expires': [error]})

        with self.assertRaises(Certificate.DoesNotExist):
            Certificate.objects.get(cn=cn)

    def test_add_no_cas(self):
        CertificateAuthority.objects.update(enabled=False)
        response = self.client.get(self.add_url)
        self.assertEqual(response.status_code, 403)

        cn = 'test-add.example.com'
        response = self.client.post(self.add_url, data={
            'csr': self.csr_pem,
            'ca': self.ca.pk,
            'profile': 'webserver',
            'subject_0': 'US',
            'subject_5': cn,
            'subjectAltName_1': True,
            'algorithm': 'SHA256',
            'expires': '2018-04-12',
            'keyUsage_0': ['digitalSignature', 'keyAgreement', ],
            'keyUsage_1': True,
            'extendedKeyUsage_0': ['clientAuth', 'serverAuth', ],
            'extendedKeyUsage_1': False,
        })
        self.assertEqual(response.status_code, 403)

    def test_add_unusable_cas(self):
        CertificateAuthority.objects.update(private_key_path='/does/not/exist')

        # check that we have some enabled CAs, just to make sure this test is really useful
        self.assertTrue(CertificateAuthority.objects.filter(enabled=True).exists())

        response = self.client.get(self.add_url)
        self.assertEqual(response.status_code, 403)

        cn = 'test-add.example.com'
        response = self.client.post(self.add_url, data={
            'csr': self.csr_pem,
            'ca': self.ca.pk,
            'profile': 'webserver',
            'subject_0': 'US',
            'subject_5': cn,
            'subjectAltName_1': True,
            'algorithm': 'SHA256',
            'expires': '2018-04-12',
            'keyUsage_0': ['digitalSignature', 'keyAgreement', ],
            'keyUsage_1': True,
            'extendedKeyUsage_0': ['clientAuth', 'serverAuth', ],
            'extendedKeyUsage_1': False,
        })
        self.assertEqual(response.status_code, 403)


class CSRDetailTestCase(AdminTestMixin, DjangoCAWithCSRTestCase):
    def setUp(self):
        self.url = reverse('admin:django_ca_certificate_csr_details')
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
        User.objects.create_user(username='plain', password='password', email='plain@example.com')
        self.assertTrue(client.login(username='plain', password='password'))

        response = client.post(self.url, data={'csr': self.csr_pem})
        self.assertRequiresLogin(response)

    def test_no_perms(self):
        # User is staff but has no permissions
        client = Client()
        User.objects.create_user(username='staff', password='password', email='staff@example.com',
                                 is_staff=True)
        self.assertTrue(client.login(username='staff', password='password'))

        response = client.post(self.url, data={'csr': self.csr_pem})
        self.assertEqual(response.status_code, 403)

    def test_no_staff(self):
        # User isn't staff but has permissions
        client = Client()
        user = User.objects.create_user(username='no_perms', password='password',
                                        email='no_perms@example.com')
        p = Permission.objects.get(codename='change_certificate')
        user.user_permissions.add(p)
        self.assertTrue(client.login(username='no_perms', password='password'))

        response = client.post(self.url, data={'csr': self.csr_pem})
        self.assertRequiresLogin(response)


class CertDownloadTestCase(AdminTestMixin, DjangoCAWithCertTestCase):
    def get_url(self, cert):
        return reverse('admin:django_ca_certificate_download', kwargs={'pk': cert.pk})

    @property
    def url(self):
        return self.get_url(cert=self.cert)

    def test_basic(self):
        filename = '%s.pem' % self.cert.serial
        response = self.client.get('%s?format=PEM' % self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/pkix-cert')
        self.assertEqual(response['Content-Disposition'], 'attachment; filename=%s' % filename)
        self.assertEqual(force_text(response.content), self.cert.pub)

    def test_der(self):
        filename = '%s.der' % self.cert.serial
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
        User.objects.create_user(username='no_perms', password='password', email='user@example.com',
                                 is_staff=True)
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


class RevokeCertViewTestCase(AdminTestMixin, DjangoCAWithCertTestCase):
    def get_url(self, cert):
        return reverse('admin:django_ca_certificate_revoke', kwargs={'pk': cert.pk})

    @property
    def url(self):
        return self.get_url(cert=self.cert)

    def test_get(self):
        self.client.get(self.url)

    def test_no_reason(self):
        response = self.client.post(self.url, data={'revoked_reason': ''})
        self.assertRedirects(response, self.change_url())
        self.assertTemplateUsed('django_ca/admin/certificate_revoke_form.html')
        self.assertRevoked(self.cert)

    def test_with_reason(self):
        reason = 'certificate_hold'
        response = self.client.post(self.url, data={'revoked_reason': reason})
        self.assertRedirects(response, self.change_url())
        self.assertTemplateUsed('django_ca/admin/certificate_revoke_form.html')
        self.assertRevoked(self.cert, reason=reason)

    def test_revoked(self):
        cert = Certificate.objects.get(serial=self.cert.serial)
        cert.revoked = True
        cert.save()

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 404)

        response = self.client.post(self.url, data={'revoked_reason': 'certificateHold'})
        self.assertEqual(response.status_code, 404)
        self.assertRevoked(self.cert)

    def test_anonymous(self):
        client = Client()

        response = client.get(self.url)
        self.assertRequiresLogin(response)

        response = client.post(self.url, data={})
        self.assertRequiresLogin(response)
        self.assertNotRevoked(self.cert)

    def test_plain_user(self):
        # User isn't staff and has no permissions
        client = Client()
        User.objects.create_user(username='plain', password='password', email='plain@example.com')
        self.assertTrue(client.login(username='plain', password='password'))

        response = client.get(self.url)
        self.assertRequiresLogin(response)

        response = client.post(self.url, data={})
        self.assertRequiresLogin(response)
        self.assertNotRevoked(self.cert)

    def test_no_perms(self):
        # User is staff but has no permissions
        client = Client()
        User.objects.create_user(username='staff', password='password', email='staff@example.com',
                                 is_staff=True)
        self.assertTrue(client.login(username='staff', password='password'))

        response = client.get(self.url)
        self.assertEqual(response.status_code, 403)
        self.assertNotRevoked(self.cert)

        response = client.post(self.url, data={})
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

        response = client.get(self.url)
        self.assertRequiresLogin(response)

        response = client.post(self.url, data={})
        self.assertRequiresLogin(response)
        self.assertNotRevoked(self.cert)
