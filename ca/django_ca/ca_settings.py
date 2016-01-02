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
from django.utils.translation import ugettext_lazy as _

CA_PROFILES = getattr(settings, 'CA_PROFILES', {
    'client': {
        # see: http://security.stackexchange.com/questions/68491/
        'desc': _('Issue a certificate for a client.'),
        'basicConstraints': {
            'critical': True,
            'value': 'CA:FALSE',
        },
        'keyUsage': {
            'critical': True,
            'value': [
                'digitalSignature',
            ],
        },
        'extendedKeyUsage': {
            'critical': False,
            'value': [
                'clientAuth',
            ],
        },
    },
    'server': {
        'desc': _('Issue a certificate for a server, allows client and server authentication.'),
        'basicConstraints': {
            'critical': True,
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
        # see http://security.stackexchange.com/questions/24106/
        'desc': _('Issue a certificate for a webserver.'),
        'basicConstraints': {
            'critical': True,
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
                'serverAuth',
            ],
        },
    },
    'enduser': {
        # see: http://security.stackexchange.com/questions/30066/
        'desc': _(
            '''Issue a certificate for an enduser, allows client authentication, code and email
signing.'''),
        'basicConstraints': {
            'critical': True,
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
        'desc': _('Issue a certificate for an OCSP responder.'),
        'basicConstraints': {
            'critical': True,
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
    'ca': {
        'desc': _('Issue a CA certificate.'),
        'basicConstraints': {
            'critical': True,
            'value': 'CA:TRUE',
        },
        'keyUsage': {
            'critical': True,
            'value': [
                'cRLSign',
                'keyCertSign',
            ],
        },
        'extendedKeyUsage': None,
    },
})

# Add ability just override/add some profiles
CA_CUSTOM_PROFILES = getattr(settings, 'CA_CUSTOM_PROFILES', {})
if CA_CUSTOM_PROFILES is not None:
    CA_PROFILES.update(CA_CUSTOM_PROFILES)

CA_ALLOW_CA_CERTIFICATES = getattr(settings, 'CA_ALLOW_CA_CERTIFICATES', False)
CA_DEFAULT_EXPIRES = getattr(settings, 'CA_DEFAULT_EXPIRES', 720)
CA_DEFAULT_PROFILE = getattr(settings, 'CA_DEFAULT_PROFILE', 'webserver')
