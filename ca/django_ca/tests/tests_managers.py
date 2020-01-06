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

from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID

from .. import ca_settings
from ..deprecation import RemovedInDjangoCA16Warning
from ..extensions import AuthorityInformationAccess
from ..extensions import AuthorityKeyIdentifier
from ..extensions import BasicConstraints
from ..extensions import CRLDistributionPoints
from ..extensions import DistributionPoint
from ..extensions import ExtendedKeyUsage
from ..extensions import IssuerAlternativeName
from ..extensions import KeyUsage
from ..extensions import NameConstraints
from ..extensions import OCSPNoCheck
from ..extensions import PrecertPoison
from ..extensions import SubjectAlternativeName
from ..extensions import SubjectKeyIdentifier
from ..extensions import TLSFeature
from ..models import Certificate
from ..models import CertificateAuthority
from ..profiles import profiles
from ..subject import Subject
from .base import DjangoCATestCase
from .base import DjangoCAWithCertTestCase
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
        self.assertIsNone(ca.crl_url)
        self.assertEqual(ca.crl_number, '{"scope": {}}')
        self.assertIsNone(ca.issuer_url)
        self.assertIsNone(ca.ocsp_url)
        self.assertEqual(ca.issuer_alt_name, '')

    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_extra_extensions(self):
        subject = '/CN=example.com'
        tlsf = TLSFeature({'value': ['OCSPMustStaple']})
        ca = CertificateAuthority.objects.init('with-extra', subject, extra_extensions=[tlsf])

        exts = [e for e in ca.extensions
                if not isinstance(e, (SubjectKeyIdentifier, AuthorityKeyIdentifier))]
        self.assertEqual(ca.subject, Subject(subject))
        self.assertCountEqual(exts, [
            tlsf,
            BasicConstraints({'critical': True, 'value': {'ca': True}}),
            KeyUsage({'critical': True, 'value': ['cRLSign', 'keyCertSign']}),
        ])


@override_settings(CA_DEFAULT_SUBJECT={})
class CreateCertTestCase(DjangoCAWithGeneratedCAsTestCase):
    @override_tmpcadir(CA_PROFILES={ca_settings.CA_DEFAULT_PROFILE: {'extensions': {}}})
    def test_basic(self):
        ca = self.cas['root']
        csr = certs['root-cert']['csr']['pem']
        subject = '/CN=example.com'

        cert = Certificate.objects.create_cert(ca, csr, subject=subject, add_crl_url=False,
                                               add_ocsp_url=False, add_issuer_url=False)
        self.assertEqual(cert.subject, Subject(subject))
        self.assertEqual(cert.extensions, [
            ca.get_authority_key_identifier_extension(),
            BasicConstraints({'value': {'ca': False}}),
            SubjectAlternativeName({'value': ['DNS:example.com']}),
            certs['root-cert']['subject_key_identifier'],
        ])

    @override_tmpcadir(CA_PROFILES={ca_settings.CA_DEFAULT_PROFILE: {'extensions': {}}})
    def test_explicit_profile(self):
        ca = self.cas['root']
        csr = certs['root-cert']['csr']['pem']
        subject = '/CN=example.com'

        cert = Certificate.objects.create_cert(
            ca, csr, subject=subject, profile=profiles[ca_settings.CA_DEFAULT_PROFILE],
            add_crl_url=False, add_ocsp_url=False, add_issuer_url=False)
        self.assertEqual(cert.subject, Subject(subject))
        self.assertEqual(cert.extensions, [
            ca.get_authority_key_identifier_extension(),
            BasicConstraints({'value': {'ca': False}}),
            SubjectAlternativeName({'value': ['DNS:example.com']}),
            certs['root-cert']['subject_key_identifier'],
        ])

    @override_tmpcadir(CA_PROFILES={k: None for k in ca_settings.CA_PROFILES})
    def test_no_profile(self):
        ca = self.cas['root']
        csr = certs['root-cert']['csr']['pem']
        subject = '/CN=example.com'

        with self.assertRaisesRegex(KeyError, r"^'webserver'$"):
            Certificate.objects.create_cert(ca, csr, subject=subject, add_crl_url=False, add_ocsp_url=False,
                                            add_issuer_url=False)


@override_settings(CA_PROFILES={}, CA_DEFAULT_SUBJECT={})
class GetCertTestCase(DjangoCAWithCertTestCase):
    def assertExtensions(self, cert, expected):
        expected['BasicConstraints'] = BasicConstraints({'critical': True, 'value': {'ca': False}})
        expected['AuthorityKeyIdentifier'] = AuthorityKeyIdentifier(cert.ca.subject_key_identifier)

        if cert.ca.issuer_alt_name:
            expected['issuerAltName'] = 'URI:%s' % self.ca.issuer_alt_name

        exts = self.get_extensions(cert.x509)
        key_id = exts.pop('SubjectKeyIdentifier')
        self.assertFalse(key_id.critical)
        self.assertEqual(len(key_id.as_text()), 59)

        self.assertEqual(exts, expected)

    def cert_init(self, *args, **kwargs):
        with self.assertMultipleWarnings([{
            'category': RemovedInDjangoCA16Warning, 'filename': __file__,
            'msg': r'^Function will be removed in django-ca 1.16$',
        }]):
            return Certificate.objects.init(*args, **kwargs)

    @override_tmpcadir()
    def test_basic(self):
        kwargs = self.get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])

        ca = self.cas['child']
        csr = certs['child-cert']['csr']['pem']
        cert = self.cert_init(ca, csr, algorithm='SHA256',
                              subject_alternative_name={'value': ['example.com']}, **kwargs)
        cert.full_clean()

        self.assertBasic(cert.x509)

        # verify subject
        expected_subject = [('CN', 'example.com'), ]
        self.assertSubject(cert.x509, expected_subject)

        # verify extensions
        extensions = {
            'AuthorityInformationAccess': AuthorityInformationAccess({'value': {
                'issuers': [ca.issuer_url],
                'ocsp': [ca.ocsp_url],
            }}),
            'CRLDistributionPoints': CRLDistributionPoints({'value': [
                {'full_name': ca.crl_url},
            ]}),
            'ExtendedKeyUsage': ExtendedKeyUsage({'value': ['serverAuth']}),
            'KeyUsage': KeyUsage({
                'critical': True,
                'value': ['digitalSignature', 'keyAgreement', 'keyEncipherment']
            }),
            'SubjectAlternativeName': SubjectAlternativeName({'value': ['DNS:example.com']}),
        }

        self.assertExtensions(cert, extensions)

    @override_tmpcadir()
    def test_no_subject(self):
        ca = self.cas['child']
        csr = certs['child-cert']['csr']['pem']
        kwargs = self.get_cert_profile_kwargs()
        del kwargs['subject']
        cert = self.cert_init(ca, csr, subject_alternative_name={'value': ['example.com']}, **kwargs)
        cert.full_clean()

        self.assertSubject(cert.x509, [('CN', 'example.com')])

        # verify extensions
        self.assertExtensions(cert, {
            'AuthorityInformationAccess': AuthorityInformationAccess({'value': {
                'ocsp': [ca.ocsp_url],
                'issuers': [ca.issuer_url],
            }}),
            'CRLDistributionPoints': CRLDistributionPoints({'value': [
                {'full_name': [ca.crl_url]},
            ]}),
            'ExtendedKeyUsage': ExtendedKeyUsage({'value': ['serverAuth']}),
            'KeyUsage': KeyUsage({
                'value': ['digitalSignature', 'keyAgreement', 'keyEncipherment'],
            }),
            'SubjectAlternativeName': SubjectAlternativeName({'value': ['DNS:example.com']}),
        })

    @override_tmpcadir()
    def test_san_extension(self):
        # subject_alternative_name as an extension
        kwargs = self.get_cert_profile_kwargs()

        ca = self.cas['child']
        csr = certs['child-cert']['csr']['pem']
        cert = self.cert_init(ca, csr, algorithm='SHA256',
                              subject_alternative_name=SubjectAlternativeName({'value': ['example.com']}),
                              **kwargs)
        cert.full_clean()

        self.assertBasic(cert.x509)

        # verify subject
        expected_subject = [('CN', 'example.com'), ]
        self.assertSubject(cert.x509, expected_subject)

        # verify extensions
        extensions = {
            'AuthorityInformationAccess': AuthorityInformationAccess({'value': {
                'issuers': [ca.issuer_url],
                'ocsp': [ca.ocsp_url],
            }}),
            'CRLDistributionPoints': CRLDistributionPoints({'value': [
                {'full_name': ca.crl_url},
            ]}),
            'ExtendedKeyUsage': ExtendedKeyUsage({'value': ['serverAuth']}),
            'KeyUsage': KeyUsage({
                'critical': True,
                'value': ['digitalSignature', 'keyAgreement', 'keyEncipherment']
            }),
            'SubjectAlternativeName': SubjectAlternativeName({'value': ['DNS:example.com']}),
        }

        self.assertExtensions(cert, extensions)

    def test_no_names(self):
        ca = self.cas['child']
        csr = certs['child-cert']['csr']['pem']
        kwargs = self.get_cert_profile_kwargs()
        del kwargs['subject']

        with self.assertRaisesRegex(ValueError, r'^Must name at least a CN or a subjectAlternativeName\.$'):
            self.cert_init(ca, csr, subject_alternative_name=[], **kwargs)

        with self.assertRaisesRegex(ValueError, r'^Must name at least a CN or a subjectAlternativeName\.$'):
            self.cert_init(ca, csr, subject_alternative_name=None, **kwargs)

    @override_tmpcadir()
    def test_cn_in_san(self):
        ca = self.cas['child']
        csr = certs['child-cert']['csr']['pem']
        kwargs = self.get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])
        kwargs['subject']['CN'] = 'cn.example.com'
        cert = self.cert_init(ca, csr, algorithm=hashes.SHA256(),
                              subject_alternative_name={'value': ['example.com']}, **kwargs)

        self.assertEqual(self.get_subject(cert.x509)['CN'], 'cn.example.com')
        self.assertEqual(cert.subject_alternative_name,
                         SubjectAlternativeName({'value': ['DNS:cn.example.com', 'DNS:example.com']}))

        # try the same with no SAN at all
        cert = self.cert_init(ca, csr, algorithm=hashes.SHA256(), **kwargs)
        self.assertEqual(self.get_subject(cert.x509)['CN'], 'cn.example.com')
        self.assertEqual(cert.subject_alternative_name,
                         SubjectAlternativeName({'value': ['DNS:cn.example.com']}))

    @override_tmpcadir()
    def test_cn_not_in_san(self):
        ca = self.cas['child']
        csr = certs['child-cert']['csr']['pem']
        kwargs = self.get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])
        kwargs['subject']['CN'] = 'cn.example.com'
        kwargs['cn_in_san'] = False
        cert = self.cert_init(ca, csr, algorithm=hashes.SHA256(),
                              subject_alternative_name={'value': ['example.com']}, **kwargs)

        self.assertEqual(self.get_subject(cert.x509)['CN'], 'cn.example.com')
        self.assertEqual(cert.subject_alternative_name,
                         SubjectAlternativeName({'value': ['DNS:example.com']}))

    @override_tmpcadir()
    def test_no_san(self):
        ca = self.cas['child']
        csr = certs['child-cert']['csr']['pem']
        kwargs = self.get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])
        kwargs['subject']['CN'] = 'cn.example.com'
        kwargs['cn_in_san'] = False
        cert = self.cert_init(ca, csr, algorithm=hashes.SHA256(), **kwargs)
        self.assertEqual(self.get_subject(cert.x509)['CN'], 'cn.example.com')
        self.assertHasNotExtension(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        self.assertNotIn('SubjectAlternativeName', cert.extensions)

    @override_tmpcadir()
    def test_no_key_usage(self):
        ca = self.cas['child']
        csr = certs['child-cert']['csr']['pem']
        kwargs = self.get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])
        del kwargs['key_usage']
        cert = self.cert_init(ca, csr, algorithm=hashes.SHA256(),
                              subject_alternative_name={'value': ['example.com']}, **kwargs)
        self.assertHasNotExtension(cert, ExtensionOID.KEY_USAGE)
        self.assertHasExtension(cert, ExtensionOID.EXTENDED_KEY_USAGE)

    @override_tmpcadir()
    def test_no_ext_key_usage(self):
        ca = self.cas['child']
        csr = certs['child-cert']['csr']['pem']
        kwargs = self.get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])
        del kwargs['extended_key_usage']
        cert = self.cert_init(ca, csr, algorithm=hashes.SHA256(),
                              subject_alternative_name={'value': ['example.com']}, **kwargs)
        self.assertHasNotExtension(cert, ExtensionOID.EXTENDED_KEY_USAGE)
        self.assertHasExtension(cert, ExtensionOID.KEY_USAGE)

    @override_tmpcadir()
    def test_crl(self):
        # get from the db to make sure that values do not influence other testcases
        ca = self.cas['child']
        ca.crl_url = 'http://crl.example.com'
        ca.save()
        csr = certs['child-cert']['csr']['pem']

        kwargs = self.get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])
        cert = self.cert_init(ca, csr, algorithm=hashes.SHA256(),
                              subject_alternative_name={'value': ['example.com']}, **kwargs)
        self.assertEqual(self.get_extensions(cert.x509)['CRLDistributionPoints'],
                         CRLDistributionPoints({'value': [DistributionPoint({'full_name': [ca.crl_url]})]}))

        # test multiple URLs
        ca.crl_url = 'http://crl.example.com\nhttp://crl.example.org'
        kwargs = self.get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])
        cert = self.cert_init(
            ca, csr, algorithm=hashes.SHA256(),
            subject_alternative_name={'value': ['example.com']}, **kwargs)

        crl_a, crl_b = ca.crl_url.splitlines()
        expected = CRLDistributionPoints({'value': [
            DistributionPoint({'full_name': [crl_a]}),
            DistributionPoint({'full_name': [crl_b]}),
        ]})
        self.assertEqual(self.get_extensions(cert.x509)['CRLDistributionPoints'], expected)

    @override_tmpcadir()
    def test_issuer_alt_name(self):
        ca = self.cas['child']
        ca.issuer_alt_name = 'http://ian.example.com'
        ca.save()
        csr = certs['child-cert']['csr']['pem']

        kwargs = self.get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])
        cert = self.cert_init(
            ca, csr, algorithm=hashes.SHA256(),
            subject_alternative_name={'value': ['example.com']}, **kwargs)

        self.assertEqual(cert.issuer_alternative_name,
                         IssuerAlternativeName({'value': [ca.issuer_alt_name]}))

    @override_tmpcadir()
    def test_auth_info_access(self):
        ca = self.cas['child']
        csr = certs['child-cert']['csr']['pem']
        kwargs = self.get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])

        # test only with ocsp url
        ca.ocsp_url = 'http://ocsp.ca.example.com'
        cert = self.cert_init(
            ca, csr, algorithm=hashes.SHA256(),
            subject_alternative_name={'value': ['example.com']}, **kwargs)

        self.assertEqual(self.get_extensions(cert.x509)['AuthorityInformationAccess'],
                         AuthorityInformationAccess({'value': {
                             'ocsp': [ca.ocsp_url],
                             'issuers': [ca.issuer_url]
                         }}))

        # test with both ocsp_url and issuer_url
        ca.issuer_url = 'http://ca.example.com/ca.crt'
        cert = self.cert_init(
            ca, csr, algorithm=hashes.SHA256(),
            subject_alternative_name={'value': ['example.com']}, **kwargs)

        self.assertEqual(self.get_extensions(cert.x509)['AuthorityInformationAccess'],
                         AuthorityInformationAccess({
                             'value': {
                                 'issuers': [ca.issuer_url],
                                 'ocsp': [ca.ocsp_url]
                             }
                         }))

        # test only with issuer url
        ca.ocsp_url = None
        cert = self.cert_init(
            ca, csr, algorithm=hashes.SHA256(),
            subject_alternative_name={'value': ['example.com']}, **kwargs)

        self.assertEqual(self.get_extensions(cert.x509)['AuthorityInformationAccess'],
                         AuthorityInformationAccess({'value': {'issuers': [ca.issuer_url]}}))

    @override_tmpcadir()
    def test_ocsp(self):
        # Create a typical OCSP responder certificate
        ca = self.cas['child']
        csr = certs['profile-ocsp']['csr']['pem']
        san = certs['profile-ocsp']['cn']
        kwargs = self.get_cert_profile_kwargs('ocsp')

        # NOTE: ocsp_url is cleared here, b/c the OCSP profile now disables the OCSP url. But the old
        # function we test here always sets it.
        ca.ocsp_url = ''
        ca.save()

        cert = self.cert_init(
            ca, csr, algorithm=hashes.SHA256(),
            subject_alternative_name={'value': [san]},
            ocsp_no_check=True,
            **kwargs)
        self.maxDiff = None

        self.assertEqual(cert.extensions, [
            certs['profile-ocsp']['authority_information_access'],
            certs['profile-ocsp']['authority_key_identifier'],
            certs['profile-ocsp']['basic_constraints'],
            certs['profile-ocsp']['crl_distribution_points'],
            certs['profile-ocsp']['extended_key_usage'],
            certs['profile-ocsp']['key_usage'],
            OCSPNoCheck(),
            certs['profile-ocsp']['subject_alternative_name'],
            certs['profile-ocsp']['subject_key_identifier'],
        ])

    @override_tmpcadir()
    def test_all_extensions(self):
        # Create a certificate with all extensions enabled.
        # Note that we just blindly add all extensions possible, even if they don't make sense for a
        # end-user certificate. For example, NameConstraints only makes sense for CAs.

        ca = self.cas['child']
        csr = certs['child-cert']['csr']['pem']
        cn = 'all-extensions.example.com'
        ku = {'critical': True, 'value': ['encipherOnly', 'keyAgreement', 'nonRepudiation']}
        eku = {'value': ['serverAuth', 'clientAuth', 'codeSigning', 'emailProtection']}
        tlsf = {'critical': True, 'value': ['OCSPMustStaple', 'MultipleCertStatusRequest']}
        san = 'extra.example.com'
        nc = {'value': {'permitted': ['.com'], 'excluded': ['.net']}}
        subject = '/CN=%s' % cn

        ian = {'value': ['http://ian.example.com']}
        ca.ocsp_url = certs['child']['ocsp_url']
        ca.issuer_url = certs['child']['issuer_url']
        ca.crl_url = certs['child']['crl_url']
        ca.save()

        extra_extensions = [
            NameConstraints(nc), IssuerAlternativeName(ian),
            OCSPNoCheck({'critical': True}),
            PrecertPoison(),
        ]

        cert = self.cert_init(
            ca, csr,
            subject=subject,
            subject_alternative_name={'value': [san]},
            key_usage=ku,
            extended_key_usage=eku,
            tls_feature=tlsf,
            extra_extensions=extra_extensions,
        )

        self.assertEqual(cert.subject, Subject(subject))
        self.assertEqual(cert.extensions, [
            certs['all-extensions']['authority_information_access'],
            certs['all-extensions']['authority_key_identifier'],
            certs['all-extensions']['basic_constraints'],
            certs['all-extensions']['crl_distribution_points'],
            certs['all-extensions']['extended_key_usage'],
            IssuerAlternativeName(ian),
            certs['all-extensions']['key_usage'],
            NameConstraints(nc),
            OCSPNoCheck({'critical': True}),
            PrecertPoison(),
            SubjectAlternativeName({'value': [cn, san]}),
            certs['child-cert']['subject_key_identifier'],  # -> where the CSR/public key comes from
            certs['all-extensions']['tls_feature'],
        ])

    @override_tmpcadir()
    def test_override_ca_extensions(self):
        ca = self.cas['child']
        csr = certs['child-cert']['csr']['pem']
        cn = 'override.example.com'
        subject = '/CN=%s' % cn

        issuer_url = 'http://issuer.override.example.com'
        crl_url = 'http://crl.override.example.com'
        ocsp_url = 'http://ocsp.override.example.com'
        ian_url = {'value': ['http://ian.override.example.com']}

        ca.issuer_url = ''
        ca.crl_url = ''
        ca.ocsp_url = ''
        ca.issuer_alt_name_url = ''
        ca.save()

        cert = self.cert_init(
            ca, csr, subject=subject,
            issuer_url=issuer_url, crl_url=crl_url, ocsp_url=ocsp_url, issuer_alternative_name=ian_url
        )

        self.assertEqual(cert.extensions, [
            AuthorityInformationAccess({'value': {'issuers': [issuer_url], 'ocsp': [ocsp_url]}}),
            certs['child-cert']['authority_key_identifier'],
            BasicConstraints({'value': {'ca': False}}),
            CRLDistributionPoints({'value': [{'full_name': [crl_url]}]}),
            IssuerAlternativeName(ian_url),
            SubjectAlternativeName({'value': [cn]}),
            certs['child-cert']['subject_key_identifier'],
        ])

    @override_tmpcadir()
    def test_clear_ca_extensions(self):
        ca = self.cas['child']
        csr = certs['child-cert']['csr']['pem']
        cn = 'override.example.com'
        subject = '/CN=%s' % cn

        issuer_url = 'http://issuer.override.example.com'
        crl_url = 'http://crl.override.example.com'
        ocsp_url = 'http://ocsp.override.example.com'
        ian_url = 'http://ian.override.example.com'

        ca.issuer_url = issuer_url
        ca.crl_url = crl_url
        ca.ocsp_url = ocsp_url
        ca.issuer_alt_name_url = ian_url
        ca.save()

        cert = self.cert_init(
            ca, csr, subject=subject,
            issuer_url=False, crl_url=False, ocsp_url=False, issuer_alternative_name=False
        )

        self.assertEqual(cert.extensions, [
            certs['child-cert']['authority_key_identifier'],
            BasicConstraints({'value': {'ca': False}}),
            SubjectAlternativeName({'value': [cn]}),
            certs['child-cert']['subject_key_identifier'],
        ])

    @override_tmpcadir()
    def test_extra_extensions(self):
        ca = self.cas['child']
        csr = certs['child-cert']['csr']['pem']
        cn = 'all-extensions.example.com'
        ku = {'critical': True, 'value': ['encipherOnly', 'keyAgreement', 'nonRepudiation']}
        eku = {'value': ['serverAuth', 'clientAuth', 'codeSigning', 'emailProtection']}
        tlsf = {'critical': True, 'value': ['OCSPMustStaple', 'MultipleCertStatusRequest']}
        san = ['extra.example.com']
        nc = {'value': {'permitted': ['.com'], 'excluded': ['.net']}}
        ian = 'https://ca.example.com'
        subject = '/CN=%s' % cn

        extra_extensions = [
            NameConstraints(nc).as_extension(),
            IssuerAlternativeName({'value': [ian]}).as_extension(),
            OCSPNoCheck({'critical': True}).as_extension(),
        ]

        cert = self.cert_init(
            ca, csr,
            subject=subject,
            subject_alternative_name={'value': san},
            key_usage=ku,
            extended_key_usage=eku,
            tls_feature=tlsf,
            extra_extensions=extra_extensions,
        )

        self.assertEqual(cert.subject, Subject(subject))
        self.assertEqual(cert.extensions, [
            AuthorityInformationAccess({'value': {'issuers': [ca.issuer_url], 'ocsp': [ca.ocsp_url], }}),
            certs['child-cert']['authority_key_identifier'],
            BasicConstraints({'critical': True, 'value': {'ca': False}}),
            CRLDistributionPoints({'value': [{'full_name': ca.crl_url}, ]}),
            ExtendedKeyUsage(eku),
            IssuerAlternativeName({'value': [ian]}),
            KeyUsage(ku),
            NameConstraints(nc),
            OCSPNoCheck({'critical': True}),
            SubjectAlternativeName({'value': [cn] + san}),  # prepend CN from subject
            certs['child-cert']['subject_key_identifier'],
            TLSFeature(tlsf),
        ])

    def test_extra_extensions_value(self):
        ca = self.cas['child']
        csr = certs['child-cert']['csr']['pem']
        with self.assertRaisesRegex(ValueError, r'^Cannot add extension of type bool$'):
            self.cert_init(
                ca, csr, subject_alternative_name={'value': ['example.com']},
                extra_extensions=[False])

    def test_invalid_name(self):
        cn = 'foo bar'
        msg = r'^%s: Could not parse CommonName as subjectAlternativeName\.$' % cn
        with self.assertRaisesRegex(ValueError, msg):
            self.cert_init(self.cas['child'], certs['child-cert']['csr']['pem'],
                           subject=Subject('/CN=%s' % cn))
