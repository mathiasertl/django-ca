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

from django.conf import settings

CA_PROFILES = getattr(settings, 'CA_PROFILES', {
    'client': {
        'basicConstraints': {
            'critical': False,
            'value': 'CA:FALSE',
        },
        'keyUsage': {
            'critical': True,
            'value': [
                'dataEncipherment',
                'digitalSignature',
                'keyEncipherment',
            ],
        },
        'extendedKeyUsage': {
            'critical': False,
            'value': [
                'clientAuth',
                'emailProtection',
            ],
        },
    },
    'server': {
        'basicConstraints': {
            'critical': False,
            'value': 'CA:FALSE',
        },
        'keyUsage': {
            'critical': True,
            'value': [
                'digitalSignature',
                'keyAgreement',
                'keyEncipherment',
            ],
        },
        'extendedKeyUsage': {
            'critical': False,
            'value': [
                'clientAuth',
                'serverAuth',
            ],
        },
    },
    'webserver': {
        'basicConstraints': {
            'critical': False,
            'value': 'CA:FALSE',
        },
        'keyUsage': {
            'critical': True,
            'value': [
                'digitalSignature',
                'keyAgreement',
                'keyEncipherment',
            ],
        },
        'extendedKeyUsage': {
            'critical': False,
            'value': [
                'clientAuth',
                'serverAuth',
            ],
        },
    },
    'enduser': {
        'basicConstraints': {
            'critical': False,
            'value': 'CA:FALSE',
        },
        'keyUsage': {
            'critical': True,
            'value': [
                'dataEncipherment',
                'digitalSignature',
                'keyEncipherment',
            ],
        },
        'extendedKeyUsage': {
            'critical': False,
            'value': [
                'clientAuth',
                'codeSigning',
                'emailProtection',
            ],
        },
    },
    'ocsp': {
        'basicConstraints': {
            'critical': False,
            'value': 'CA:FALSE',
        },
        'keyUsage': {
            'critical': True,
            'value': [
                'nonRepudiation',
                'digitalSignature',
                'keyEncipherment',
            ],
        },
        'extendedKeyUsage': {
            'critical': False,
            'value': [
                'OCSPSigning',
            ],
        },
    },
})

# Add ability just override/add some profiles
CA_CUSTOM_PROFILES = getattr(settings, 'CA_CUSTOM_PROFILES', {})
if CA_CUSTOM_PROFILES is not None:
    CA_PROFILES.update(CA_CUSTOM_PROFILES)
