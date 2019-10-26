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
from ..extensions import TLSFeature
from ..profiles import get_cert_profile_kwargs
from .base import DjangoCATestCase
from .base import override_settings


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
        'ocsp': {
            'ocsp_no_check': True,
        },
    })
    def test_ocsp_no_check(self):
        self.maxDiff = None
        expected = {
            'cn_in_san': True,
            'key_usage': KeyUsage({
                'critical': True,
                'value': ['nonRepudiation', 'digitalSignature', 'keyEncipherment']
            }),
            'extended_key_usage': ExtendedKeyUsage({'value': ['OCSPSigning']}),
            'ocsp_no_check': True,
            'subject': {
                'C': 'AT',
                'ST': 'Vienna',
                'L': 'Vienna',
                'O': 'Django CA',
                'OU': 'Django CA Testsuite',
            },
        }
        self.assertEqual(get_cert_profile_kwargs('ocsp'), expected)

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
