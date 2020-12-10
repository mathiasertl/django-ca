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

from urllib.parse import quote

from django.contrib.auth.models import User
from django.templatetags.static import static
from django.test import Client
from django.test import override_settings
from django.urls import reverse
from django.utils.encoding import force_str

from .base import DjangoCAWithCATestCase
from .base import certs


class CertificateAuthorityAdminTestMixin(object):
    def setUp(self):
        self.user = User.objects.create_superuser(username='user', password='password',
                                                  email='user@example.com')
        self.add_url = reverse('admin:django_ca_certificateauthority_add')
        self.changelist_url = reverse('admin:django_ca_certificateauthority_changelist')
        self.client = Client()
        self.client.force_login(self.user)
        super(CertificateAuthorityAdminTestMixin, self).setUp()

    def assertCSS(self, response, path):
        css = '<link href="%s" type="text/css" media="all" rel="stylesheet" />' % static(path)
        self.assertInHTML(css, response.content.decode('utf-8'), 1)

    def change_url(self, pk=None):
        if pk is None:
            pk = self.cas['root'].pk

        return reverse('admin:django_ca_certificateauthority_change', args=(pk, ))

    def assertChangeResponse(self, response):
        self.assertEqual(response.status_code, 200)

        templates = [t.name for t in response.templates]
        self.assertIn('admin/change_form.html', templates)
        self.assertCSS(response, 'django_ca/admin/css/base.css')
        self.assertCSS(response, 'django_ca/admin/css/certificateauthorityadmin.css')

    def assertRequiresLogin(self, response, **kwargs):
        expected = '%s?next=%s' % (reverse('admin:login'), quote(response.wsgi_request.get_full_path()))
        self.assertRedirects(response, expected, **kwargs)


class ChangelistTestCase(CertificateAuthorityAdminTestMixin, DjangoCAWithCATestCase):
    """Test the changelist view."""

    def assertResponse(self, response, certs=None):
        if certs is None:
            certs = []

        self.assertEqual(response.status_code, 200)
        self.assertCSS(response, 'django_ca/admin/css/base.css')
        self.assertCSS(response, 'django_ca/admin/css/certificateauthorityadmin.css')
        self.assertEqual(set(response.context['cl'].result_list), set(certs))

    def test_get(self):
        response = self.client.get(self.changelist_url)
        self.assertResponse(response, self.cas.values())

    def test_unauthorized(self):
        client = Client()
        response = client.get(self.changelist_url)
        self.assertRequiresLogin(response)


class ChangeTestCase(CertificateAuthorityAdminTestMixin, DjangoCAWithCATestCase):
    """Test the change view."""

    def test_basic(self):
        """Test that viewing a CA at least does not throw an exception."""
        for ca in self.cas.values():
            response = self.client.get(self.change_url(ca.pk))
            self.assertChangeResponse(response)

    @override_settings(CA_ENABLE_ACME=False)
    def test_with_acme(self):
        """Basic tests but with ACME support disabled."""
        self.test_basic()


class CADownloadBundleTestCase(CertificateAuthorityAdminTestMixin, DjangoCAWithCATestCase):
    def get_url(self, ca):
        return reverse('admin:django_ca_certificateauthority_download_bundle', kwargs={'pk': ca.pk})

    @property
    def url(self):
        return self.get_url(ca=self.cas['root'])

    def test_root(self):
        filename = 'root_example_com_bundle.pem'
        response = self.client.get('%s?format=PEM' % self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/pkix-cert')
        self.assertEqual(response['Content-Disposition'], 'attachment; filename=%s' % filename)
        self.assertEqual(force_str(response.content), certs['root']['pub']['pem'].strip())

    def test_child(self):
        filename = 'child_example_com_bundle.pem'
        response = self.client.get('%s?format=PEM' % self.get_url(self.cas['child']))
        expected = '%s\n%s' % (certs['child']['pub']['pem'].strip(), certs['root']['pub']['pem'].strip())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/pkix-cert')
        self.assertEqual(response['Content-Disposition'], 'attachment; filename=%s' % filename)
        self.assertEqual(force_str(response.content), expected)

    def test_invalid_format(self):
        response = self.client.get('%s?format=INVALID' % self.url)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.content, b'')

        # DER is not supported for bundles
        response = self.client.get('%s?format=DER' % self.url)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.content, b'DER/ASN.1 certificates cannot be downloaded as a bundle.')
