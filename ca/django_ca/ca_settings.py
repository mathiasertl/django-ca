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

import os

from django.conf import settings
from django.utils.translation import ugettext_lazy as _

CA_DIR = getattr(settings, 'CA_DIR', os.path.join(settings.BASE_DIR, 'files'))

CA_PROFILES = {
    'client': {
        # see: http://security.stackexchange.com/questions/68491/
        'desc': _('A certificate for a client.'),
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
        'desc': _('A certificate for a server, allows client and server authentication.'),
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
        'desc': _('A certificate for a webserver.'),
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
            'A certificate for an enduser, allows client authentication, code and email signing.'),
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
        'cn_in_san': False,
    },
    'ocsp': {
        'desc': _('A certificate for an OCSP responder.'),
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
}

_CA_DEFAULT_SUBJECT = getattr(settings, 'CA_DEFAULT_SUBJECT', {})
for name, profile in CA_PROFILES.items():
    profile['subject'] = _CA_DEFAULT_SUBJECT
    profile.setdefault('cn_in_san', True)

# Add ability just override/add some profiles
_CA_PROFILE_OVERRIDES = getattr(settings, 'CA_PROFILES', {})
for name, profile in _CA_PROFILE_OVERRIDES.items():
    if profile is None:
        del CA_PROFILES[name]

    elif name in CA_PROFILES:
        CA_PROFILES[name].update(profile)
    else:
        profile.setdefault('subject', _CA_DEFAULT_SUBJECT)
        profile.setdefault('cn_in_san', True)
        CA_PROFILES[name] = profile

CA_DEFAULT_EXPIRES = getattr(settings, 'CA_DEFAULT_EXPIRES', 730)
CA_DEFAULT_PROFILE = getattr(settings, 'CA_DEFAULT_PROFILE', 'webserver')
CA_DIGEST_ALGORITHM = getattr(settings, 'CA_DIGEST_ALGORITHM', "sha512")
CA_NOTIFICATION_DAYS = getattr(settings, 'CA_NOTIFICATION_DAYS', [14, 7, 3, 1, ])

# Undocumented options, e.g. to share values between different parts of code
CA_MIN_KEY_SIZE = getattr(settings, 'CA_MIN_KEY_SIZE', 2048)
CA_PROVIDE_GENERIC_CRL = getattr(settings, 'CA_PROVIDE_GENERIC_CRL', True)
