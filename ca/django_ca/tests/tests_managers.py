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

from .. import ca_settings
from ..extensions import AuthorityKeyIdentifier
from ..extensions import BasicConstraints
from ..extensions import KeyUsage
from ..extensions import OCSPNoCheck
from ..extensions import SubjectAlternativeName
from ..extensions import SubjectKeyIdentifier
from ..extensions import TLSFeature
from ..models import Certificate
from ..models import CertificateAuthority
from ..profiles import profiles
from ..subject import Subject
from .base import DjangoCATestCase
from .base import DjangoCAWithGeneratedCAsTestCase
from .base import certs
from .base import override_settings
from .base import override_tmpcadir


@override_settings(CA_PROFILES={}, CA_DEFAULT_SUBJECT={}, )
class CertificateAuthorityManagerTestCase(DjangoCATestCase):
    def assertBasic(self, ca, name, subject):
        base_url = 'http://%s/django_ca/' % ca_settings.CA_DEFAULT_HOSTNAME
        self.assertEqual(ca.name, name)
        self.assertEqual(ca.subject, Subject(subject))
        self.assertTrue(ca.enabled)
        self.assertIsNone(ca.parent)
        self.assertEqual(ca.crl_url, '%scrl/%s/' % (base_url, ca.serial))
        self.assertEqual(ca.crl_number, '{"scope": {}}')
        self.assertEqual(ca.issuer_url, '%sissuer/%s.der' % (base_url, ca.serial))
        self.assertEqual(ca.ocsp_url, '%socsp/%s/cert/' % (base_url, ca.serial))
        self.assertEqual(ca.issuer_alt_name, '')

    @override_tmpcadir()
    def test_basic(self):
        name = 'basic'
        subject = '/CN=example.com'
        self.assertBasic(CertificateAuthority.objects.init(name, subject), name, subject)

    @override_tmpcadir()
    def test_no_default_hostname(self):
        name = 'ndh'
        subject = '/CN=ndh.example.com'
        ca = CertificateAuthority.objects.init(name, subject, default_hostname=False)
        self.assertEqual(ca.crl_url, '')
        self.assertEqual(ca.crl_number, '{"scope": {}}')
        self.assertIsNone(ca.issuer_url)
        self.assertIsNone(ca.ocsp_url)
        self.assertEqual(ca.issuer_alt_name, '')

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_extra_extensions(self):
        subject = '/CN=example.com'
        tlsf = TLSFeature({'value': ['OCSPMustStaple']})
        ocsp_no_check = OCSPNoCheck()
        ca = CertificateAuthority.objects.init('with-extra', subject, extra_extensions=[
            tlsf, ocsp_no_check.as_extension()
        ])

        exts = [e for e in ca.extensions
                if not isinstance(e, (SubjectKeyIdentifier, AuthorityKeyIdentifier))]
        self.assertEqual(ca.subject, Subject(subject))
        self.assertCountEqual(exts, [
            tlsf,
            ocsp_no_check,
            BasicConstraints({'critical': True, 'value': {'ca': True}}),
            KeyUsage({'critical': True, 'value': ['cRLSign', 'keyCertSign']}),
        ])

    def test_unknown_extension_type(self):
        name = 'unknown-extension-type'
        subject = '/CN=%s.example.com' % name
        with self.assertRaisesRegex(ValueError, r'^Cannot add extension of type bool$'):
            CertificateAuthority.objects.init(name, subject, extra_extensions=[True])
        self.assertEqual(CertificateAuthority.objects.filter(name=name).count(), 0)


@override_settings(CA_DEFAULT_SUBJECT={})
class CreateCertTestCase(DjangoCAWithGeneratedCAsTestCase):
    @override_tmpcadir(CA_PROFILES={ca_settings.CA_DEFAULT_PROFILE: {'extensions': {}}})
    def test_basic(self):
        ca = self.cas['root']
        csr = certs['root-cert']['csr']['pem']
        subject = '/CN=example.com'

        cert = Certificate.objects.create_cert(ca, csr, subject=subject)
        self.assertEqual(cert.subject, Subject(subject))
        self.assertExtensions(cert, [
            SubjectAlternativeName({'value': ['DNS:example.com']}),
        ])

    @override_tmpcadir(CA_PROFILES={ca_settings.CA_DEFAULT_PROFILE: {'extensions': {}}})
    def test_explicit_profile(self):
        ca = self.cas['root']
        csr = certs['root-cert']['csr']['pem']
        subject = '/CN=example.com'

        cert = Certificate.objects.create_cert(
            ca, csr, subject=subject, profile=profiles[ca_settings.CA_DEFAULT_PROFILE])
        self.assertEqual(cert.subject, Subject(subject))
        self.assertExtensions(cert, [
            SubjectAlternativeName({'value': ['DNS:example.com']}),
        ])

    @override_tmpcadir()
    def test_no_cn_or_san(self):
        ca = self.cas['root']
        csr = certs['root-cert']['csr']['pem']
        subject = None

        msg = r"^Must name at least a CN or a subjectAlternativeName\.$"
        with self.assertRaisesRegex(ValueError, msg):
            Certificate.objects.create_cert(ca, csr, subject=subject, extensions=[SubjectAlternativeName()])

    @override_tmpcadir(CA_PROFILES={k: None for k in ca_settings.CA_PROFILES})
    def test_no_profile(self):
        ca = self.cas['root']
        csr = certs['root-cert']['csr']['pem']
        subject = '/CN=example.com'

        with self.assertRaisesRegex(KeyError, r"^'webserver'$"):
            Certificate.objects.create_cert(ca, csr, subject=subject, add_crl_url=False, add_ocsp_url=False,
                                            add_issuer_url=False)
