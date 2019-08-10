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

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID

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
from ..profiles import get_cert_profile_kwargs
from ..subject import Subject
from .base import DjangoCATestCase
from .base import DjangoCAWithCertTestCase
from .base import certs
from .base import override_settings
from .base import override_tmpcadir


@override_settings(CA_PROFILES={}, CA_DEFAULT_SUBJECT={})
class CertificateAuthorityManagerTestCase(DjangoCATestCase):
    @override_tmpcadir(CA_MIN_KEY_SIZE=1024)
    def test_extra_extensions(self):
        subject = '/CN=example.com'
        tlsf = TLSFeature('OCSPMustStaple')
        ca = CertificateAuthority.objects.init('with-extra', '/CN=example.com', extra_extensions=[tlsf])

        exts = [e for e in ca.extensions
                if not isinstance(e, (SubjectKeyIdentifier, AuthorityKeyIdentifier))]
        self.assertEqual(ca.subject, Subject(subject))
        self.assertCountEqual(exts, [
            tlsf,
            BasicConstraints('critical,CA:True'),
            KeyUsage('critical,cRLSign,keyCertSign'),
        ])


@override_settings(CA_PROFILES={}, CA_DEFAULT_SUBJECT={})
class GetCertTestCase(DjangoCAWithCertTestCase):
    def assertExtensions(self, cert, expected):
        expected['BasicConstraints'] = BasicConstraints('critical,CA:FALSE')
        expected['AuthorityKeyIdentifier'] = AuthorityKeyIdentifier(cert.ca.subject_key_identifier)

        if cert.ca.issuer_alt_name:
            expected['issuerAltName'] = 'URI:%s' % self.ca.issuer_alt_name

        # TODO: Does not account for multiple CRLs yet
        if cert.ca.crl_url:
            expected['crlDistributionPoints'] = '\nFull Name:\n  URI:%s\n' % cert.ca.crl_url

        auth_info_access = ''
        if cert.ca.ocsp_url:
            auth_info_access += 'OCSP - URI:%s\n' % cert.ca.ocsp_url
        if cert.ca.issuer_url:
            auth_info_access += 'CA Issuers - URI:%s\n' % cert.ca.issuer_url
        if auth_info_access:
            expected['authorityInfoAccess'] = auth_info_access

        exts = self.get_extensions(cert.x509)

        key_id = exts.pop('SubjectKeyIdentifier')
        self.assertFalse(key_id.critical)
        self.assertEqual(len(key_id.as_text()), 59)

        self.assertEqual(exts, expected)

    @override_tmpcadir()
    def test_basic(self):
        kwargs = get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])

        ca = self.cas['child']
        csr = certs['child-cert']['csr']['pem']
        cert = Certificate.objects.init(
            ca, csr, algorithm='SHA256',
            subject_alternative_name=['example.com'], **kwargs)
        cert.full_clean()

        self.assertBasic(cert.x509)

        # verify subject
        expected_subject = [
            ('CN', 'example.com'),
        ]
        self.assertSubject(cert.x509, expected_subject)

        # verify extensions
        extensions = {
            'ExtendedKeyUsage': ExtendedKeyUsage('serverAuth'),
            'KeyUsage': KeyUsage('critical,digitalSignature,keyAgreement,keyEncipherment'),
            'SubjectAlternativeName': SubjectAlternativeName('DNS:example.com'),
        }

        self.assertExtensions(cert, extensions)

    @override_tmpcadir()
    def test_no_subject(self):
        ca = self.cas['child']
        csr = certs['child-cert']['csr']['pem']
        kwargs = get_cert_profile_kwargs()
        del kwargs['subject']
        cert = Certificate.objects.init(
            ca, csr,
            subject_alternative_name=['example.com'], **kwargs)
        cert.full_clean()

        self.assertSubject(cert.x509, [('CN', 'example.com')])

        # verify extensions
        self.assertExtensions(cert, {
            'ExtendedKeyUsage': ExtendedKeyUsage('serverAuth'),
            'KeyUsage': KeyUsage('critical,digitalSignature,keyAgreement,keyEncipherment'),
            'SubjectAlternativeName': SubjectAlternativeName('DNS:example.com'),
        })

    def test_no_names(self):
        ca = self.cas['child']
        csr = certs['child-cert']['csr']['pem']
        kwargs = get_cert_profile_kwargs()
        del kwargs['subject']

        with self.assertRaisesRegex(ValueError, r'^Must name at least a CN or a subjectAlternativeName\.$'):
            Certificate.objects.init(ca, csr, subject_alternative_name=[], **kwargs)

        with self.assertRaisesRegex(ValueError, r'^Must name at least a CN or a subjectAlternativeName\.$'):
            Certificate.objects.init(ca, csr, subject_alternative_name=None, **kwargs)

    @override_tmpcadir()
    def test_cn_in_san(self):
        ca = self.cas['child']
        csr = certs['child-cert']['csr']['pem']
        kwargs = get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])
        kwargs['subject']['CN'] = 'cn.example.com'
        cert = Certificate.objects.init(
            ca, csr, algorithm=hashes.SHA256(),
            subject_alternative_name=['example.com'], **kwargs)

        self.assertEqual(self.get_subject(cert.x509)['CN'], 'cn.example.com')
        self.assertEqual(cert.subject_alternative_name,
                         SubjectAlternativeName('DNS:cn.example.com,DNS:example.com'))

        # try the same with no SAN at all
        cert = Certificate.objects.init(
            ca, csr, algorithm=hashes.SHA256(), **kwargs)
        self.assertEqual(self.get_subject(cert.x509)['CN'], 'cn.example.com')
        self.assertEqual(cert.subject_alternative_name, SubjectAlternativeName('DNS:cn.example.com'))

    @override_tmpcadir()
    def test_cn_not_in_san(self):
        ca = self.cas['child']
        csr = certs['child-cert']['csr']['pem']
        kwargs = get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])
        kwargs['subject']['CN'] = 'cn.example.com'
        kwargs['cn_in_san'] = False
        cert = Certificate.objects.init(
            ca, csr, algorithm=hashes.SHA256(),
            subject_alternative_name=['example.com'], **kwargs)

        self.assertEqual(self.get_subject(cert.x509)['CN'], 'cn.example.com')
        self.assertEqual(cert.subject_alternative_name, SubjectAlternativeName('DNS:example.com'))

    @override_tmpcadir()
    def test_no_san(self):
        ca = self.cas['child']
        csr = certs['child-cert']['csr']['pem']
        kwargs = get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])
        kwargs['subject']['CN'] = 'cn.example.com'
        kwargs['cn_in_san'] = False
        cert = Certificate.objects.init(
            ca, csr, algorithm=hashes.SHA256(), **kwargs)
        self.assertEqual(self.get_subject(cert.x509)['CN'], 'cn.example.com')
        self.assertHasNotExtension(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        self.assertNotIn('SubjectAlternativeName', cert.extensions)

    @override_tmpcadir()
    def test_no_key_usage(self):
        ca = self.cas['child']
        csr = certs['child-cert']['csr']['pem']
        kwargs = get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])
        del kwargs['key_usage']
        cert = Certificate.objects.init(
            ca, csr, algorithm=hashes.SHA256(),
            subject_alternative_name=['example.com'], **kwargs)
        self.assertHasNotExtension(cert, ExtensionOID.KEY_USAGE)
        self.assertHasExtension(cert, ExtensionOID.EXTENDED_KEY_USAGE)

    @override_tmpcadir()
    def test_no_ext_key_usage(self):
        ca = self.cas['child']
        csr = certs['child-cert']['csr']['pem']
        kwargs = get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])
        del kwargs['extended_key_usage']
        cert = Certificate.objects.init(
            ca, csr, algorithm=hashes.SHA256(),
            subject_alternative_name=['example.com'], **kwargs)
        self.assertHasNotExtension(cert, ExtensionOID.EXTENDED_KEY_USAGE)
        self.assertHasExtension(cert, ExtensionOID.KEY_USAGE)

    @override_tmpcadir()
    def test_crl(self):
        # get from the db to make sure that values do not influence other testcases
        ca = self.cas['child']
        ca.crl_url = 'http://crl.example.com'
        ca.save()
        csr = certs['child-cert']['csr']['pem']

        kwargs = get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])
        cert = Certificate.objects.init(
            ca, csr, algorithm=hashes.SHA256(),
            subject_alternative_name=['example.com'], **kwargs)
        self.assertEqual(self.get_extensions(cert.x509)['CRLDistributionPoints'],
                         CRLDistributionPoints([DistributionPoint({'full_name': [ca.crl_url]})]))

        # test multiple URLs
        ca.crl_url = 'http://crl.example.com\nhttp://crl.example.org'
        kwargs = get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])
        cert = Certificate.objects.init(
            ca, csr, algorithm=hashes.SHA256(),
            subject_alternative_name=['example.com'], **kwargs)

        crl_a, crl_b = ca.crl_url.splitlines()
        expected = CRLDistributionPoints([
            DistributionPoint({'full_name': [crl_a]}),
            DistributionPoint({'full_name': [crl_b]}),
        ])
        self.assertEqual(self.get_extensions(cert.x509)['CRLDistributionPoints'], expected)

    @override_tmpcadir()
    def test_issuer_alt_name(self):
        ca = self.cas['child']
        ca.issuer_alt_name = 'http://ian.example.com'
        ca.save()
        csr = certs['child-cert']['csr']['pem']

        kwargs = get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])
        cert = Certificate.objects.init(
            ca, csr, algorithm=hashes.SHA256(),
            subject_alternative_name=['example.com'], **kwargs)

        self.assertEqual(cert.issuer_alternative_name,
                         IssuerAlternativeName(ca.issuer_alt_name))

    @override_tmpcadir()
    def test_auth_info_access(self):
        ca = self.cas['child']
        csr = certs['child-cert']['csr']['pem']
        kwargs = get_cert_profile_kwargs()
        kwargs['subject'] = Subject(kwargs['subject'])

        # test only with ocsp url
        ca.ocsp_url = 'http://ocsp.ca.example.com'
        cert = Certificate.objects.init(
            ca, csr, algorithm=hashes.SHA256(),
            subject_alternative_name=['example.com'], **kwargs)

        self.assertEqual(self.get_extensions(cert.x509)['AuthorityInformationAccess'],
                         AuthorityInformationAccess([[], [ca.ocsp_url]]))

        # test with both ocsp_url and issuer_url
        ca.issuer_url = 'http://ca.example.com/ca.crt'
        cert = Certificate.objects.init(
            ca, csr, algorithm=hashes.SHA256(),
            subject_alternative_name=['example.com'], **kwargs)

        self.assertEqual(self.get_extensions(cert.x509)['AuthorityInformationAccess'],
                         AuthorityInformationAccess([[ca.issuer_url], [ca.ocsp_url]]))

        # test only with issuer url
        ca.ocsp_url = None
        cert = Certificate.objects.init(
            ca, csr, algorithm=hashes.SHA256(),
            subject_alternative_name=['example.com'], **kwargs)

        self.assertEqual(self.get_extensions(cert.x509)['AuthorityInformationAccess'],
                         AuthorityInformationAccess([[ca.issuer_url], []]))

    @override_tmpcadir()
    def test_ocsp(self):
        # Create a typical OCSP responder certificate
        ca = self.cas['child']
        csr = certs['profile-ocsp']['csr']['pem']
        san = certs['profile-ocsp']['cn']
        kwargs = get_cert_profile_kwargs('ocsp')

        ca.ocsp_url = certs['child']['ocsp_url']
        ca.issuer_url = certs['child']['issuer_url']
        ca.crl_url = certs['child']['crl_url']
        ca.save()

        cert = Certificate.objects.init(
            ca, csr, algorithm=hashes.SHA256(),
            subject_alternative_name=[san],
            ocsp_no_check=True,
            **kwargs)

        self.assertCountEqual(cert.extensions, [
            cert.subject_key_identifier,  # changes on every invocation
            certs['profile-ocsp']['authority_information_access'],
            certs['profile-ocsp']['authority_key_identifier'],
            certs['profile-ocsp']['basic_constraints'],
            certs['profile-ocsp']['extended_key_usage'],
            certs['profile-ocsp']['key_usage'],
            certs['profile-ocsp']['subject_alternative_name'],
            OCSPNoCheck(),
            certs['profile-ocsp']['crl_distribution_points'],
        ])

    @override_tmpcadir()
    def test_all_extensions(self):
        # Create a certificate with all extensions enabled.
        # Note that we just blindly add all extensions possible, even if they don't make sense for a
        # end-user certificate. For example, NameConstraints only makes sense for CAs.

        ca = self.cas['child']
        csr = certs['child-cert']['csr']['pem']
        cn = 'all-extensions.example.com'
        ku = 'critical,encipherOnly,keyAgreement,nonRepudiation'
        eku = 'serverAuth,clientAuth,codeSigning,emailProtection'
        tlsf = 'critical,OCSPMustStaple,MultipleCertStatusRequest'
        san = 'extra.example.com'
        nc = [['.com'], ['.net']]
        subject = '/CN=%s' % cn

        ian = 'http://ian.example.com'
        ca.ocsp_url = certs['child']['ocsp_url']
        ca.issuer_url = certs['child']['issuer_url']
        ca.crl_url = certs['child']['crl_url']
        ca.save()

        extra_extensions = [
            NameConstraints(nc), IssuerAlternativeName(ian),
            OCSPNoCheck({'critical': True}),
            PrecertPoison(),
        ]

        cert = Certificate.objects.init(
            ca, csr,
            subject=subject,
            subject_alternative_name=[san],
            key_usage=ku,
            extended_key_usage=eku,
            tls_feature=tlsf,
            extra_extensions=extra_extensions,
        )

        self.assertEqual(cert.subject, Subject(subject))
        expected = [
            cert.subject_key_identifier,  # changes on every invocation
            certs['all-extensions']['authority_information_access'],
            certs['all-extensions']['authority_key_identifier'],
            certs['all-extensions']['basic_constraints'],
            certs['all-extensions']['extended_key_usage'],
            certs['all-extensions']['key_usage'],
            OCSPNoCheck({'critical': True}),
            SubjectAlternativeName('%s,%s' % (cn, san)),
            IssuerAlternativeName(ian),
            certs['all-extensions']['tls_feature'],
            NameConstraints(nc),
            certs['all-extensions']['crl_distribution_points'],
            PrecertPoison(),
        ]
        self.assertCountEqual(cert.extensions, expected)

    @override_tmpcadir()
    def test_override_ca_extensions(self):
        ca = self.cas['child']
        csr = certs['child-cert']['csr']['pem']
        cn = 'override.example.com'
        subject = '/CN=%s' % cn

        issuer_url = 'http://issuer.override.example.com'
        crl_url = 'http://crl.override.example.com'
        ocsp_url = 'http://ocsp.override.example.com'
        ian_url = 'http://ian.override.example.com'

        ca.issuer_url = ''
        ca.crl_url = ''
        ca.ocsp_url = ''
        ca.issuer_alt_name_url = ''
        ca.save()

        cert = Certificate.objects.init(
            ca, csr, subject=subject,
            issuer_url=issuer_url, crl_url=crl_url, ocsp_url=ocsp_url, issuer_alternative_name=ian_url
        )
        aki = AuthorityKeyIdentifier(x509.Extension(
            oid=AuthorityKeyIdentifier.oid, critical=False,
            value=ca.get_authority_key_identifier()
        ))

        self.maxDiff = None
        expected = [
            cert.subject_key_identifier,  # changes on every invocation
            BasicConstraints({'value': {'ca': False}}),
            aki,
            CRLDistributionPoints({'value': [{'full_name': [crl_url]}]}),
            SubjectAlternativeName({'value': [cn]}),
            AuthorityInformationAccess({
                'value': {
                    'issuers': [issuer_url],
                    'ocsp': [ocsp_url],
                }
            }),
            IssuerAlternativeName({'value': [ian_url]}),
        ]

        self.assertCountEqual(cert.extensions, expected)

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

        cert = Certificate.objects.init(
            ca, csr, subject=subject,
            issuer_url=False, crl_url=False, ocsp_url=False, issuer_alternative_name=False
        )
        aki = AuthorityKeyIdentifier(x509.Extension(
            oid=AuthorityKeyIdentifier.oid, critical=False,
            value=ca.get_authority_key_identifier()
        ))

        self.maxDiff = None
        expected = [
            cert.subject_key_identifier,  # changes on every invocation
            BasicConstraints({'value': {'ca': False}}),
            aki,
            SubjectAlternativeName({'value': [cn]}),
        ]

        self.assertCountEqual(cert.extensions, expected)

    @override_tmpcadir()
    def test_extra_extensions(self):
        ca = self.cas['child']
        csr = certs['child-cert']['csr']['pem']
        cn = 'all-extensions.example.com'
        ku = 'critical,encipherOnly,keyAgreement,nonRepudiation'
        eku = 'serverAuth,clientAuth,codeSigning,emailProtection'
        tlsf = 'critical,OCSPMustStaple,MultipleCertStatusRequest'
        san = ['extra.example.com']
        nc = [['.com'], ['.net']]
        ian = 'https://ca.example.com'
        subject = '/CN=%s' % cn

        self.maxDiff = None
        extra_extensions = [
            NameConstraints(nc).as_extension(),
            IssuerAlternativeName(ian).as_extension(),
            OCSPNoCheck({'critical': True}).as_extension(),
        ]

        cert = Certificate.objects.init(
            ca, csr,
            subject=subject,
            subject_alternative_name=san,
            key_usage=ku,
            extended_key_usage=eku,
            tls_feature=tlsf,
            extra_extensions=extra_extensions,
        )

        aki = AuthorityKeyIdentifier(x509.Extension(
            oid=AuthorityKeyIdentifier.oid, critical=False,
            value=ca.get_authority_key_identifier()
        ))

        exts = [e for e in cert.extensions if not isinstance(e, SubjectKeyIdentifier)]
        self.assertEqual(cert.subject, Subject(subject))
        self.assertCountEqual(exts, [
            TLSFeature(tlsf),
            aki,
            BasicConstraints('critical,CA:False'),
            ExtendedKeyUsage(eku),
            SubjectAlternativeName([cn] + san),  # prepend CN from subject
            KeyUsage(ku),
            NameConstraints(nc),
            IssuerAlternativeName(ian),
            OCSPNoCheck({'critical': True}),
        ])

    def test_extra_extensions_value(self):
        ca = self.cas['child']
        csr = certs['child-cert']['csr']['pem']
        with self.assertRaisesRegex(ValueError, r'^Cannot add extension of type bool$'):
            Certificate.objects.init(
                ca, csr, subject_alternative_name=['example.com'],
                extra_extensions=[False])
