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

"""Test :py:mod:`django_ca.profiles`."""

import doctest
from datetime import timedelta

from .. import ca_settings
from ..extensions import AuthorityInformationAccess
from ..extensions import BasicConstraints
from ..extensions import CRLDistributionPoints
from ..extensions import IssuerAlternativeName
from ..extensions import KeyUsage
from ..extensions import OCSPNoCheck
from ..extensions import SubjectAlternativeName
from ..extensions import SubjectKeyIdentifier
from ..models import Certificate
from ..profiles import Profile
from ..profiles import get_profile
from ..profiles import profile
from ..profiles import profiles
from ..signals import pre_issue_cert
from ..subject import Subject
from ..utils import parse_hash_algorithm
from .base import DjangoCATestCase
from .base import certs
from .base import override_settings
from .base import override_tmpcadir


@override_settings(CA_MIN_KEY_SIZE=1024, CA_DEFAULT_KEY_SIZE=1024)
class DocumentationTestCase(DjangoCATestCase):
    """Test sphinx docs."""
    def setUp(self):
        super().setUp()
        self.ca = self.load_ca(name=certs['root']['name'], parsed=certs['root']['pub']['parsed'])

    def get_globs(self):
        """Get globals for doctests."""
        return {
            'Profile': Profile,
            'get_profile': get_profile,
            'ca': self.ca,
            'ca_serial': self.ca.serial,
            'csr': certs['root-cert']['csr']['parsed'],
        }

    @override_tmpcadir()
    def test_module(self):
        """Test doctests from main module."""
        # pylint: disable=redefined-outer-name,import-outside-toplevel; we need the top-level module
        from .. import profiles
        doctest.testmod(profiles, globs=self.get_globs())

    @override_tmpcadir()
    def test_python_intro(self):
        """Test python/profiles.rst."""
        doctest.testfile('../../../docs/source/python/profiles.rst', globs=self.get_globs())


class ProfileTestCase(DjangoCATestCase):
    """Main tests for the profile class."""

    def create_cert(self, prof, *args, **kwargs):  # pylint: disable=arguments-differ
        """Shortcut to create a cert with the given profile."""
        cert = Certificate()
        cert.x509 = prof.create_cert(*args, **kwargs)
        return cert

    def test_copy(self):
        """Test copying a profile."""
        prof1 = Profile('example')
        prof2 = prof1.copy()
        self.assertIsNot(prof1, prof2)
        self.assertEqual(prof1, prof2)
        prof2.extensions[SubjectAlternativeName.key] = SubjectAlternativeName({'value': ['example.com']})
        self.assertNotEqual(prof1, prof2)
        self.assertNotIn(SubjectAlternativeName.key, prof1.extensions)
        self.assertIn(SubjectAlternativeName.key, prof2.extensions)

        # test algorithm b/c cryptography does not compare this properly
        prof2 = prof1.copy()
        prof2.algorithm = parse_hash_algorithm('MD5')
        self.assertNotEqual(prof1, prof2)

    def test_eq(self):
        """Test profile equality."""
        prof = None
        for name in ca_settings.CA_PROFILES:
            self.assertNotEqual(prof, profiles[name])
            prof = profiles[name]
            self.assertEqual(prof, prof)
            self.assertNotEqual(prof, None)
            self.assertNotEqual(prof, -1)

    def test_init_django_ca_values(self):
        """Test django-ca extensions as extensions."""
        prof1 = Profile('test', subject=Subject('/C=AT/CN=example.com'), extensions={
            OCSPNoCheck.key: {},
        })
        prof2 = Profile('test', subject='/C=AT/CN=example.com', extensions={
            OCSPNoCheck.key: OCSPNoCheck(),
        })
        self.assertEqual(prof1, prof2)

    def test_init_no_subject(self):
        """Test with no default subject."""
        # doesn't really occur in the wild, because ca_settings updates CA_PROFILES with the default
        # subject. But it still seems sensible to support this
        default_subject = {'CN': 'testcase'}

        with override_settings(CA_DEFAULT_SUBJECT=default_subject):
            prof = Profile('test')
        self.assertEqual(prof.subject, Subject(default_subject))

    def test_init_expires(self):
        """Test the expire parameter."""
        prof = Profile('example', expires=30)
        self.assertEqual(prof.expires, timedelta(days=30))

        exp = timedelta(hours=3)
        prof = Profile('example', expires=exp)
        self.assertEqual(prof.expires, exp)

    def test_serialize(self):
        """Test profile serialization."""

        desc = 'foo bar'
        kusage = ['digitalSignature']
        subject = {'CN': 'example.com'}
        prof = Profile('test', cn_in_san=True, description=desc, subject=Subject(subject), extensions={
            KeyUsage.key: {'value': kusage},
        })
        self.assertEqual(prof.serialize(), {
            'cn_in_san': True,
            'subject': subject,
            'description': desc,
            'extensions': {
                BasicConstraints.key: {
                    'value': {'ca': False},
                    'critical': BasicConstraints.default_critical,
                },
                KeyUsage.key: {
                    'value': kusage,
                    'critical': KeyUsage.default_critical,
                }
            },
        })

    @override_tmpcadir()
    def test_create_cert_minimal(self):
        """Create a certificate with minimal parameters."""
        ca = self.load_ca(name='root', parsed=certs['root']['pub']['parsed'])
        csr = certs['child-cert']['csr']['parsed']
        subject = Subject({'CN': 'example.com'})

        prof = Profile('example', subject=Subject())
        with self.assertSignal(pre_issue_cert) as pre:
            cert = self.create_cert(prof, ca, csr, subject=subject, add_crl_url=False, add_ocsp_url=False,
                                    add_issuer_url=False, add_issuer_alternative_name=False)
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(cert.subject, subject)
        self.assertEqual(cert.extensions, [
            ca.get_authority_key_identifier_extension(),
            BasicConstraints({'value': {'ca': False}}),
            SubjectAlternativeName({'value': ['DNS:example.com']}),
            certs['child-cert']['subject_key_identifier'],
        ])

    @override_tmpcadir()
    def test_alternative_values(self):
        """Test overriding most values."""
        ca = self.load_ca(name='root', parsed=certs['root']['pub']['parsed'])
        ca.issuer_alt_name = 'https://example.com'
        ca.save()
        csr = certs['child-cert']['csr']['parsed']
        subject = Subject({'C': 'AT', 'CN': 'example.com'})
        issuer = Subject('/CN=issuer.example.com')

        prof = Profile('example', subject=Subject(), issuer_name=issuer)
        with self.assertSignal(pre_issue_cert) as pre:
            cert = self.create_cert(prof, ca, csr, subject='/C=AT', algorithm='SHA256',
                                    expires=timedelta(days=30), extensions=[
                                        SubjectAlternativeName({'value': ['example.com']})
                                    ])
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(cert.subject, subject)
        self.assertEqual(cert.extensions, [
            AuthorityInformationAccess({'value': {
                'issuers': [ca.issuer_url],
                'ocsp': [ca.ocsp_url],
            }}),
            ca.get_authority_key_identifier_extension(),
            BasicConstraints({'value': {'ca': False}}),
            CRLDistributionPoints({'value': [{'full_name': [ca.crl_url]}]}),
            IssuerAlternativeName({'value': [ca.issuer_alt_name]}),
            SubjectAlternativeName({'value': ['DNS:example.com']}),
            certs['child-cert']['subject_key_identifier'],
        ])

    @override_tmpcadir()
    def test_overrides(self):
        """Test other overrides."""
        ca = self.load_ca(name='root', parsed=certs['root']['pub']['parsed'])
        csr = certs['child-cert']['csr']['parsed']
        cname = 'example.com'
        subject = Subject({'C': 'AT', 'CN': cname})

        prof = Profile('example', subject=Subject({'C': 'AT'}), add_crl_url=False, add_ocsp_url=False,
                       add_issuer_url=False, add_issuer_alternative_name=False)
        with self.assertSignal(pre_issue_cert) as pre:
            cert = self.create_cert(prof, ca, csr, subject=Subject({'CN': cname}))
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(cert.subject, subject)
        self.assertEqual(cert.extensions, [
            ca.get_authority_key_identifier_extension(),
            BasicConstraints({'value': {'ca': False}}),
            SubjectAlternativeName({'value': ['DNS:example.com']}),
            certs['child-cert']['subject_key_identifier'],
        ])

        with self.assertSignal(pre_issue_cert) as pre:
            cert = self.create_cert(prof, ca, csr, subject=subject, add_crl_url=True, add_ocsp_url=True,
                                    add_issuer_url=True, add_issuer_alternative_name=True)
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(cert.subject, subject)
        self.assertEqual(cert.extensions, [
            AuthorityInformationAccess({'value': {
                'issuers': [ca.issuer_url],
                'ocsp': [ca.ocsp_url],
            }}),
            ca.get_authority_key_identifier_extension(),
            BasicConstraints({'value': {'ca': False}}),
            CRLDistributionPoints({'value': [{'full_name': [ca.crl_url]}]}),
            SubjectAlternativeName({'value': ['DNS:example.com']}),
            certs['child-cert']['subject_key_identifier'],
        ])

    @override_tmpcadir()
    def test_cn_in_san(self):
        """Test writing the common name into the SAN."""
        ca = self.load_ca(name='root', parsed=certs['root']['pub']['parsed'])
        csr = certs['child-cert']['csr']['parsed']
        cname = 'example.com'
        subject = Subject({'C': 'AT', 'CN': cname})

        prof = Profile('example', subject=Subject({'C': 'AT'}), add_crl_url=False, add_ocsp_url=False,
                       add_issuer_url=False, add_issuer_alternative_name=False, cn_in_san=False)
        with self.assertSignal(pre_issue_cert) as pre:
            cert = self.create_cert(prof, ca, csr, subject=Subject({'CN': cname}))
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(cert.subject, subject)
        self.assertEqual(cert.extensions, [
            ca.get_authority_key_identifier_extension(),
            BasicConstraints({'value': {'ca': False}}),
            certs['child-cert']['subject_key_identifier'],
        ])

        # Create the same cert, but pass cn_in_san=True to create_cert
        with self.assertSignal(pre_issue_cert) as pre:
            cert = self.create_cert(prof, ca, csr, subject=Subject({'CN': cname}), cn_in_san=True)
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(cert.subject, subject)
        self.assertEqual(cert.extensions, [
            ca.get_authority_key_identifier_extension(),
            BasicConstraints({'value': {'ca': False}}),
            SubjectAlternativeName({'value': ['DNS:example.com']}),
            certs['child-cert']['subject_key_identifier'],
        ])

        # test that cn_in_san=True with a SAN that already contains the CN does not lead to a duplicate
        with self.assertSignal(pre_issue_cert) as pre:
            cert = self.create_cert(
                prof, ca, csr, subject=Subject({'CN': cname}), cn_in_san=True, extensions=[
                    SubjectAlternativeName({'value': ['DNS:example.com']}),
                ]
            )
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(cert.subject, subject)
        self.assertEqual(cert.extensions, [
            ca.get_authority_key_identifier_extension(),
            BasicConstraints({'value': {'ca': False}}),
            SubjectAlternativeName({'value': ['DNS:example.com']}),
            certs['child-cert']['subject_key_identifier'],
        ])

        # test that the first SAN is added as CN if we don't have A CN
        with self.assertSignal(pre_issue_cert) as pre:
            cert = self.create_cert(
                prof, ca, csr, cn_in_san=True, extensions=[
                    SubjectAlternativeName({'value': ['DNS:example.com']}),
                ]
            )
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(cert.subject, subject)
        self.assertEqual(cert.extensions, [
            ca.get_authority_key_identifier_extension(),
            BasicConstraints({'value': {'ca': False}}),
            SubjectAlternativeName({'value': ['DNS:example.com']}),
            certs['child-cert']['subject_key_identifier'],
        ])

    @override_tmpcadir()
    def test_override_ski(self):
        """Test overriding the subject key identifier."""
        ca = self.load_ca(name='root', parsed=certs['root']['pub']['parsed'])
        csr = certs['child-cert']['csr']['parsed']
        subject = Subject({'CN': 'example.com'})
        ski = SubjectKeyIdentifier({'value': b'333333'})

        prof = Profile('example', subject=Subject())
        with self.assertSignal(pre_issue_cert) as pre:
            cert = self.create_cert(prof, ca, csr, subject=subject, add_crl_url=False, add_ocsp_url=False,
                                    add_issuer_url=False, add_issuer_alternative_name=False,
                                    extensions=[ski])
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(cert.subject, subject)
        self.assertEqual(cert.extensions, [
            ca.get_authority_key_identifier_extension(),
            BasicConstraints({'value': {'ca': False}}),
            SubjectAlternativeName({'value': ['DNS:example.com']}),
            ski,
        ])

    @override_tmpcadir()
    def test_extensions_dict(self):
        """Test with a dict for an extension."""
        ca = self.load_ca(name='root', parsed=certs['root']['pub']['parsed'])
        csr = certs['child-cert']['csr']['parsed']
        subject = Subject({'CN': 'example.com'})
        ski = SubjectKeyIdentifier({'value': b'333333'})

        prof = Profile('example', subject=Subject())
        with self.assertSignal(pre_issue_cert) as pre:
            cert = self.create_cert(prof, ca, csr, subject=subject, add_crl_url=False, add_ocsp_url=False,
                                    add_issuer_url=False, add_issuer_alternative_name=False,
                                    extensions={ski.key: ski})
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(cert.subject, subject)
        self.assertEqual(cert.extensions, [
            ca.get_authority_key_identifier_extension(),
            BasicConstraints({'value': {'ca': False}}),
            SubjectAlternativeName({'value': ['DNS:example.com']}),
            ski,
        ])

    @override_tmpcadir()
    def test_hide_extension(self):
        """Test with hiding extensions from the profile."""
        ca = self.load_ca(name='root', parsed=certs['root']['pub']['parsed'])
        csr = certs['child-cert']['csr']['parsed']
        subject = Subject({'CN': 'example.com'})

        prof = Profile('example', subject=Subject(), extensions={OCSPNoCheck.key: {}})
        with self.assertSignal(pre_issue_cert) as pre:
            cert = self.create_cert(prof, ca, csr, subject=subject, add_crl_url=False, add_ocsp_url=False,
                                    add_issuer_url=False, add_issuer_alternative_name=False,
                                    extensions={OCSPNoCheck.key: None})
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(cert.subject, subject)
        self.assertEqual(cert.extensions, [
            ca.get_authority_key_identifier_extension(),
            BasicConstraints({'value': {'ca': False}}),
            SubjectAlternativeName({'value': ['DNS:example.com']}),
            certs['child-cert']['subject_key_identifier'],
        ])

    @override_tmpcadir()
    def test_extension_as_cryptography(self):
        """Test with a profile that has cryptography extensions."""
        ca = self.load_ca(name='root', parsed=certs['root']['pub']['parsed'])
        csr = certs['child-cert']['csr']['parsed']
        subject = Subject({'CN': 'example.com'})

        prof = Profile('example', subject=Subject(), extensions={OCSPNoCheck.key: {}})
        with self.assertSignal(pre_issue_cert) as pre:
            cert = self.create_cert(prof, ca, csr, subject=subject, add_crl_url=False, add_ocsp_url=False,
                                    add_issuer_url=False, add_issuer_alternative_name=False,
                                    extensions={OCSPNoCheck.key: OCSPNoCheck().as_extension()})
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(cert.subject, subject)
        self.assertEqual(cert.extensions, [
            ca.get_authority_key_identifier_extension(),
            BasicConstraints({'value': {'ca': False}}),
            OCSPNoCheck(),
            SubjectAlternativeName({'value': ['DNS:example.com']}),
            certs['child-cert']['subject_key_identifier'],
        ])

    @override_tmpcadir()
    def test_no_cn_no_san(self):
        """Test creating a cert with no cn in san."""
        ca = self.load_ca(name='root', parsed=certs['root']['pub']['parsed'])
        csr = certs['child-cert']['csr']['parsed']

        prof = Profile('example', subject=Subject({'C': 'AT'}))
        msg = r'^Must name at least a CN or a subjectAlternativeName\.$'
        with self.assertSignal(pre_issue_cert) as pre, self.assertRaisesRegex(ValueError, msg):
            self.create_cert(prof, ca, csr, subject=Subject())
        self.assertEqual(pre.call_count, 0)

        # pass an empty SAN
        with self.assertSignal(pre_issue_cert) as pre, self.assertRaisesRegex(ValueError, msg):
            self.create_cert(prof, ca, csr, cn_in_san=True, extensions=[SubjectAlternativeName()])
        self.assertEqual(pre.call_count, 0)

    @override_tmpcadir()
    def test_unparsable_cn(self):
        """Try creating a profile with an unparseable Common Name."""
        ca = self.load_ca(name='root', parsed=certs['root']['pub']['parsed'])
        csr = certs['child-cert']['csr']['parsed']
        cname = 'foo bar'

        prof = Profile('example', subject=Subject({'C': 'AT'}))
        msg = r'^%s: Could not parse CommonName as subjectAlternativeName\.$' % cname
        with self.assertSignal(pre_issue_cert) as pre, self.assertRaisesRegex(ValueError, msg):
            self.create_cert(prof, ca, csr, subject=Subject({'CN': cname}))
        self.assertEqual(pre.call_count, 0)

    def test_str(self):
        """Test str()."""
        for name in ca_settings.CA_PROFILES:
            self.assertEqual(str(profiles[name]), "<Profile: '%s'>" % name)

    def test_repr(self):
        """Test repr()."""
        for name in ca_settings.CA_PROFILES:
            self.assertEqual(repr(profiles[name]), "<Profile: '%s'>" % name)


class GetProfileTestCase(DjangoCATestCase):
    """Test the get_profile function."""

    def test_basic(self):
        """Basic tests."""
        for name in ca_settings.CA_PROFILES:
            prof = get_profile(name)
            self.assertEqual(name, prof.name)

        prof = get_profile()
        self.assertEqual(prof.name, ca_settings.CA_DEFAULT_PROFILE)


class ProfilesTestCase(DjangoCATestCase):
    """Tests the ``profiles`` proxy."""

    def test_basic(self):
        """Some basic tests."""
        for name in ca_settings.CA_PROFILES:
            prof = profiles[name]
            self.assertEqual(prof.name, name)

        # Run a second time, b/c accessor also caches stuff sometimes
        for name in ca_settings.CA_PROFILES:
            prof = profiles[name]
            self.assertEqual(prof.name, name)

    def test_none(self):
        """Test the ``None`` key."""
        self.assertEqual(profiles[None], profile)

    def test_default_proxy(self):
        """Test using the default proxy."""
        self.assertEqual(profile.name, ca_settings.CA_DEFAULT_PROFILE)
        self.assertEqual(str(profile), "<DefaultProfile: '%s'>" % ca_settings.CA_DEFAULT_PROFILE)
        self.assertEqual(repr(profile), "<DefaultProfile: '%s'>" % ca_settings.CA_DEFAULT_PROFILE)

        self.assertEqual(profile, profile)
        self.assertEqual(profile, profiles[ca_settings.CA_DEFAULT_PROFILE])
