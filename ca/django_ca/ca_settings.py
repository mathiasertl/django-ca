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

import cryptography
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtensionOID

from django.conf import global_settings
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.translation import ugettext_lazy as _

CA_DIR = getattr(settings, 'CA_DIR', os.path.join(settings.BASE_DIR, 'files'))
CA_DEFAULT_KEY_SIZE = getattr(settings, 'CA_DEFAULT_KEY_SIZE', 4096)

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

CA_DEFAULT_ENCODING = getattr(settings, 'CA_DEFAULT_ENCODING', Encoding.PEM)
CA_DEFAULT_EXPIRES = getattr(settings, 'CA_DEFAULT_EXPIRES', 730)
CA_DEFAULT_PROFILE = getattr(settings, 'CA_DEFAULT_PROFILE', 'webserver')
CA_NOTIFICATION_DAYS = getattr(settings, 'CA_NOTIFICATION_DAYS', [14, 7, 3, 1, ])

# Undocumented options, e.g. to share values between different parts of code
CA_MIN_KEY_SIZE = getattr(settings, 'CA_MIN_KEY_SIZE', 2048)

CA_DEFAULT_HOSTNAME = getattr(settings, 'CA_DEFAULT_HOSTNAME', None)

CA_DIGEST_ALGORITHM = getattr(settings, 'CA_DIGEST_ALGORITHM', "sha512").strip().upper()
try:
    CA_DIGEST_ALGORITHM = getattr(hashes, CA_DIGEST_ALGORITHM)()
except AttributeError:
    raise ImproperlyConfigured('Unkown CA_DIGEST_ALGORITHM: %s' % settings.CA_DIGEST_ALGORITHM)

if CA_MIN_KEY_SIZE > CA_DEFAULT_KEY_SIZE:
    raise ImproperlyConfigured('CA_DEFAULT_KEY_SIZE cannot be lower then %s' % CA_MIN_KEY_SIZE)

_CA_DEFAULT_ECC_CURVE = getattr(settings, 'CA_DEFAULT_ECC_CURVE', 'SECP256R1').strip()
try:
    CA_DEFAULT_ECC_CURVE = getattr(ec, _CA_DEFAULT_ECC_CURVE)()
    if not isinstance(CA_DEFAULT_ECC_CURVE, ec.EllipticCurve):
        raise ImproperlyConfigured('%s: Not an EllipticCurve.' % _CA_DEFAULT_ECC_CURVE)
except AttributeError:
    raise ImproperlyConfigured('Unkown CA_DEFAULT_ECC_CURVE: %s' % settings.CA_DEFAULT_ECC_CURVE)

CA_FILE_STORAGE = getattr(settings, 'CA_FILE_STORAGE', global_settings.DEFAULT_FILE_STORAGE)
CA_FILE_STORAGE_KWARGS = getattr(settings, 'CA_FILE_STORAGE_KWARGS', {
    'location': CA_DIR,
    'file_permissions_mode': 0o600,
    'directory_permissions_mode': 0o700,
})

# Try to decide if we can use OCSP from cryptography or not
try:  # pragma: only cryptography>=2.4
    from cryptography.x509 import ocsp  # NOQA
    CRYPTOGRAPHY_OCSP = True
except ImportError:  # pragma: only cryptography<2.4
    CRYPTOGRAPHY_OCSP = False

# pragma: only cryptography<2.4 - Added in cryptography 2.4.
CRYPTOGRAPHY_HAS_PRECERT_POISON = hasattr(ExtensionOID, 'PRECERT_POISON')

# pragma: only cryptography<2.5 - Added in cryptography 2.5.
# NOTE: OID was added in 2.4, extension only in 2.5
CRYPTOGRAPHY_HAS_IDP = hasattr(x509, 'IssuingDistributionPoint')

# Older versions of OpenSSL (and LibreSSL) cannot parse SignedCertificateTimestamps
# see: https://github.com/pyca/cryptography/blob/2.6.1/tests/x509/test_x509_ext.py#L4901-L4905
OPENSSL_SUPPORTS_SCT = default_backend()._lib.CRYPTOGRAPHY_OPENSSL_110F_OR_GREATER

CRYPTOGRAPHY_AKI_REQUIRES_EXTENSION = False
if cryptography.__version__ < '2.7':  # pragma: no branch, pragma: only cryptography<2.7
    CRYPTOGRAPHY_AKI_REQUIRES_EXTENSION = True

CA_FILE_STORAGE_URL = 'https://django-ca.readthedocs.io/en/latest/update.html#update-to-1-12-0-or-later'

CA_DJANGO_SUPPORTS_PATH = True
try:
    from django.urls import path  # NOQA
except ImportError:  # pragma: only django<=1.11
    CA_DJANGO_SUPPORTS_PATH = False
