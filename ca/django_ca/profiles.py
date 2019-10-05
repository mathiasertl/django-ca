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

import warnings
from copy import deepcopy

from . import ca_settings
from .extensions import ExtendedKeyUsage
from .extensions import KeyUsage
from .extensions import OCSPNoCheck
from .extensions import TLSFeature
from .subject import Subject
from .subject import default_subject
from .utils import get_default_subject
from .utils import parse_hash_algorithm


class Profile(object):  # pragma: no cover
    """

    What should a profile have

    * name (= id)
    * subject (e.g. with missing CN)
    * hash algorithm
    * list of extensions
    * settings:
        * cn_in_san by default?
        * when cert expires
        * add crl url?
        * add ocsp url?
    * description (for UI)

    """

    def __init__(self, name, subject=None, algorithm=None, extensions=None, cn_in_san=True, expires=None,
                 add_crl_url=True, add_ocsp_url=True, description='', **kwargs):
        self.name = name
        if isinstance(subject, Subject):
            self.subject = subject
        else:
            self.subject = Subject(subject)  # NOTE: also accepts None
        self.subject.update(default_subject)  # update default subject

        self.algorithm = parse_hash_algorithm(algorithm)
        self.extensions = extensions or {}
        self.cn_in_san = cn_in_san
        self.expires = expires or ca_settings.CA_DEFAULT_EXPIRES
        self.add_crl_url = add_ocsp_url
        self.add_ocsp_url = add_crl_url
        self.description = description

        if 'keyUsage' in kwargs:
            warnings.warn('keyUsage in profile is deprecated, use extensions -> %s instead.' % KeyUsage.key,
                          DeprecationWarning)
            self.extensions[KeyUsage.key] = KeyUsage(kwargs.pop('keyUsage'))
        if 'extendedKeyUsage' in kwargs:
            warnings.warn(
                'extendedKeyUsage in profile is deprecated, use extensions -> %s instead.'
                % ExtendedKeyUsage.key, DeprecationWarning)
            self.extensions[ExtendedKeyUsage.key] = ExtendedKeyUsage(kwargs.pop('extendedKeyUsage'))
        if 'TLSFeature' in kwargs:
            warnings.warn(
                'TLSFeature in profile is deprecated, use extensions -> %s instead.' % TLSFeature.key,
                DeprecationWarning)
            self.extensions[TLSFeature.key] = TLSFeature(kwargs.pop('TLSFeature'))
        if 'desc' in kwargs:
            warnings.warn('desc in profile is deprecated, use description instead.', DeprecationWarning)
            self.description = kwargs.pop('desc')
        if 'ocsp_no_check' in kwargs:
            warnings.warn('ocsp_no_check in profile is deprecated, use extensions -> %s instead.' %
                          OCSPNoCheck.key, DeprecationWarning)
            self.extensions[OCSPNoCheck.key] = {}

    def copy(self):
        """Create a deep copy of this profile."""

        return deepcopy(self)


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
