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

from .. import ca_settings
from ..extensions import ExtendedKeyUsage
from ..extensions import KeyUsage
from ..extensions import OCSPNoCheck
from ..extensions import TLSFeature
from ..profiles import Profile
from ..profiles import get_cert_profile_kwargs
from ..profiles import get_profile
from ..profiles import profiles
from ..profiles import profile
from ..subject import Subject
from .base import DjangoCATestCase
from .base import override_settings


class ProfileTestCase(DjangoCATestCase):
    def test_eq(self):
        p = None
        for name in ca_settings.CA_PROFILES:
            self.assertNotEqual(p, profiles[name])
            p = profiles[name]
            self.assertEqual(p, p)

    def test_init_django_ca_values(self):
        p1 = Profile('test', subject=Subject('/C=AT/CN=example.com'), extensions={
            OCSPNoCheck.key: {},
        })
        p2 = Profile('test', subject='/C=AT/CN=example.com', extensions={
            OCSPNoCheck.key: OCSPNoCheck({}),
        })
        self.assertEqual(p1, p2)

    def test_init_ld_values(self):
        name = 'example'
        subject = Subject('/C=AT/L=Vienna')
        desc = 'example description'
        ku = {'value': ['keyAgreement', 'keyEncipherment']}
        eku = {'value': ['clientAuth', 'serverAuth']}
        tf = {'value': ['OCSPMustStaple']}

        p1 = Profile(name, subject=subject, description=desc, extensions={
            KeyUsage.key: ku,
            ExtendedKeyUsage.key: eku,
            TLSFeature.key: tf,
            OCSPNoCheck.key: {},
        })
        with self.assertMultipleWarnings([
            {'category': DeprecationWarning, 'filename': __file__,
             'msg': r'^keyUsage in profile is deprecated, use extensions -> key_usage instead\.$',
            },
            {'category': DeprecationWarning, 'filename': __file__,
             'msg': r'^extendedKeyUsage in profile is deprecated, use extensions -> extended_key_usage instead\.$',   # NOQA
            },
            {'category': DeprecationWarning, 'filename': __file__,
             'msg': r'^TLSFeature in profile is deprecated, use extensions -> tls_feature instead\.$',
            },
            {'category': DeprecationWarning, 'filename': __file__,
             'msg': r'^desc in profile is deprecated, use description instead\.$',
            },
            {'category': DeprecationWarning, 'filename': __file__,
             'msg': r'^ocsp_no_check in profile is deprecated, use extensions -> ocsp_no_check instead\.$',
            },
        ]):
            p2 = Profile(name, subject=subject, desc=desc, keyUsage=ku, extendedKeyUsage=eku, TLSFeature=tf,
                         ocsp_no_check=True)

        self.assertEqual(p1, p2)

    def test_str(self):
        for name in ca_settings.CA_PROFILES:
            self.assertEqual(str(profiles[name]), "<Profile: '%s'>" % name)

    def test_repr(self):
        for name in ca_settings.CA_PROFILES:
            self.assertEqual(repr(profiles[name]), "<Profile: '%s'>" % name)


class GetProfileTestCase(DjangoCATestCase):
    def test_basic(self):
        for name in ca_settings.CA_PROFILES:
            profile = get_profile(name)
            self.assertEqual(name, profile.name)

        profile = get_profile()
        self.assertEqual(profile.name, ca_settings.CA_DEFAULT_PROFILE)


class ProfilesTestCase(DjangoCATestCase):
    def test_basic(self):
        for name in ca_settings.CA_PROFILES:
            p = profiles[name]
            self.assertEqual(p.name, name)

        # Run a second time, b/c accessor also caches stuff sometimes
        for name in ca_settings.CA_PROFILES:
            p = profiles[name]
            self.assertEqual(p.name, name)

    def test_default_proxy(self):
        self.assertEqual(profile.name, ca_settings.CA_DEFAULT_PROFILE)
        self.assertEqual(str(profile), "<DefaultProfile: '%s'>" % ca_settings.CA_DEFAULT_PROFILE)
        self.assertEqual(repr(profile), "<DefaultProfile: '%s'>" % ca_settings.CA_DEFAULT_PROFILE)

        self.assertEqual(profile, profile)
        self.assertEqual(profile, profiles[ca_settings.CA_DEFAULT_PROFILE])


class GetCertProfileKwargsTestCase(DjangoCATestCase):
    # NOTE: These test-cases will start failing if you change the default profiles.

    @override_settings(CA_PROFILES={})
    def test_default(self):
        expected = {
            'cn_in_san': True,
            'key_usage': KeyUsage({
                'critical': True,
                'value': ['digitalSignature', 'keyAgreement', 'keyEncipherment'],
            }),
            'extended_key_usage': ExtendedKeyUsage({'value': ['serverAuth']}),
            'subject': {
                'C': 'AT',
                'ST': 'Vienna',
                'L': 'Vienna',
                'O': 'Django CA',
                'OU': 'Django CA Testsuite',
            },
        }
        self.assertEqual(get_cert_profile_kwargs(), expected)
        self.assertEqual(get_cert_profile_kwargs(ca_settings.CA_DEFAULT_PROFILE), expected)

    @override_settings(CA_PROFILES={
        'ocsp-old': {
            'ocsp_no_check': True,
        },
        'ocsp-new': {
            'extensions': {
                'ocsp_no_check': {},
            },
        },
    })
    def test_ocsp_no_check(self):
        expected = {
            'cn_in_san': True,
            'ocsp_no_check': True,
            'subject': {
                'C': 'AT',
                'ST': 'Vienna',
                'L': 'Vienna',
                'O': 'Django CA',
                'OU': 'Django CA Testsuite',
            },
        }
        self.assertEqual(get_cert_profile_kwargs('ocsp-old'), expected)
        self.assertEqual(get_cert_profile_kwargs('ocsp-new'), expected)

    def test_types(self):
        expected = {
            'cn_in_san': True,
            'key_usage': KeyUsage({'value': ['digitalSignature'], 'critical': True}),
            'extended_key_usage': ExtendedKeyUsage({'critical': True, 'value': ['msKDC']}),
            'tls_feature': TLSFeature({'critical': True, 'value': ['OCSPMustStaple']}),
            'subject': {
                'C': 'AT',
                'ST': 'Vienna',
                'L': 'Vienna',
                'O': 'Django CA',
                'OU': 'Django CA Testsuite',
            },
        }

        CA_PROFILES = {
            'testprofile': {
                'keyUsage': {
                    'critical': True,
                    'value': ['digitalSignature'],
                },
                'extendedKeyUsage': {
                    'critical': True,
                    'value': ['msKDC'],
                },
                'TLSFeature': {
                    'critical': True,
                    'value': ['OCSPMustStaple'],
                },
            },
        }

        with self.settings(CA_PROFILES=CA_PROFILES):
            self.assertEqual(get_cert_profile_kwargs('testprofile'), expected)

        CA_PROFILES['testprofile']['keyUsage']['value'] = ['encipherOnly']
        expected['key_usage'] = KeyUsage({'value': ['encipherOnly']})
        with self.settings(CA_PROFILES=CA_PROFILES):
            self.assertEqual(get_cert_profile_kwargs('testprofile'), expected)

        CA_PROFILES['testprofile']['keyUsage']['value'] = []
        del expected['key_usage']
        with self.settings(CA_PROFILES=CA_PROFILES):
            self.assertEqual(get_cert_profile_kwargs('testprofile'), expected)

        # Ok, no we have *no* extensions
        expected = {
            'cn_in_san': True,
            'subject': {
                'C': 'AT',
                'ST': 'Vienna',
                'L': 'Vienna',
                'O': 'Django CA',
                'OU': 'Django CA Testsuite',
            },
        }

        CA_PROFILES = {
            'testprofile': {},
        }

        with self.settings(CA_PROFILES=CA_PROFILES):
            self.assertEqual(get_cert_profile_kwargs('testprofile'), expected)
