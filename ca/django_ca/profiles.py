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

from copy import deepcopy

from . import ca_settings
from .extensions import ExtendedKeyUsage
from .extensions import KeyUsage
from .extensions import TLSFeature
from .utils import get_default_subject


def get_cert_profile_kwargs(name=None):
    """Get kwargs suitable for get_cert X509 keyword arguments from the given profile."""

    if name is None:
        name = ca_settings.CA_DEFAULT_PROFILE

    profile = deepcopy(ca_settings.CA_PROFILES[name])
    kwargs = {
        'cn_in_san': profile['cn_in_san'],
        'subject': get_default_subject(name=name),
    }

    key_usage = profile.get('keyUsage')
    if key_usage and key_usage.get('value'):
        kwargs['key_usage'] = KeyUsage(key_usage)
    ext_key_usage = profile.get('extendedKeyUsage')
    if ext_key_usage and ext_key_usage.get('value'):
        kwargs['extended_key_usage'] = ExtendedKeyUsage(ext_key_usage)
    tls_feature = profile.get('TLSFeature')
    if tls_feature and tls_feature.get('value'):
        kwargs['tls_feature'] = TLSFeature(tls_feature)
    if profile.get('ocsp_no_check'):
        kwargs['ocsp_no_check'] = profile['ocsp_no_check']

    return kwargs
