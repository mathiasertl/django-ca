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

import idna

from . import ca_settings
from .extensions import AuthorityKeyIdentifier
from .extensions import AuthorityInformationAccess
from .extensions import BasicConstraints
from .extensions import CRLDistributionPoints
from .extensions import DistributionPoint
from .extensions import ExtendedKeyUsage
from .extensions import KeyUsage
from .extensions import OCSPNoCheck
from .extensions import SubjectAlternativeName
from .extensions import TLSFeature
from .subject import Subject
from .subject import default_subject
from .utils import get_default_subject
from .utils import parse_general_name
from .utils import parse_hash_algorithm


class Profile(object):  # pragma: no cover
    """

    Precedence of parameters:
    * CLI parameter
    * Profile value
    * CA value

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
                 issuer_name=None, add_crl_url=True, add_ocsp_url=True, add_issuer_url=True, description='',
                 **kwargs):
        self.name = name

        # self.subject is default subject with updates from subject argument
        self.subject = default_subject.copy()
        if not isinstance(subject, Subject):
            subject = Subject(subject)  # NOTE: also accepts None
        self.subject.update(subject)

        self.algorithm = parse_hash_algorithm(algorithm)
        self.extensions = extensions or {}
        self.cn_in_san = cn_in_san
        self.expires = expires or ca_settings.CA_DEFAULT_EXPIRES
        self.issuer_name = issuer_name
        self.add_crl_url = add_ocsp_url
        self.add_issuer_url = add_issuer_url
        self.add_ocsp_url = add_crl_url
        self.description = description

        # set some sane extension defaults
        self.extensions.setdefault(BasicConstraints.key, BasicConstraints({}))

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

    def __repr__(self):
        return '<Profile: %r>' % self.name

    def __str__(self):
        return repr(self)

    def copy(self):
        """Create a deep copy of this profile."""

        return deepcopy(self)

    def update_from_ca(self, ca):
        """Update data from the given CA.

        * Sets the AuthorityKeyIdentifier extension
        * Sets the OCSP url if add_ocsp_url is True
        * Sets a CRL URL if add_crl_url is True

        """
        self.extensions.setdefault(AuthorityKeyIdentifier.key, ca.get_authority_key_identifier_extension())
        if not self.issuer_name:
            self.issuer_name = Subject(ca.x509.subject)

        if self.add_crl_url and ca.crl_url:
            self.extensions.setdefault(CRLDistributionPoints.key, CRLDistributionPoints({}))
            self.extensions[CRLDistributionPoints.key].value.append(DistributionPoint({
                'full_name': [url.strip() for url in ca.crl_url.split()],
            }))

        if self.add_ocsp_url and ca.ocsp_url:
            self.extensions.setdefault(AuthorityInformationAccess.key, AuthorityInformationAccess({}))
            self.extensions[AuthorityInformationAccess.key].value['ocsp'].append(
                parse_general_name(ca.ocsp_url)
            )

        if self.add_issuer_url and ca.issuer_url:
            self.extensions.setdefault(AuthorityInformationAccess.key, AuthorityInformationAccess({}))
            self.extensions[AuthorityInformationAccess.key].value['issuers'].append(
                parse_general_name(ca.issuer_url)
            )

    def update_from_parameters(self, subject=None, expires=None, algorithm=None, extensions=None):
        if not isinstance(subject, Subject):
            subject = Subject(subject)  # NOTE: also accepts None
        self.subject.update(subject)

        if expires is not None:
            self.expires = expires
        if algorithm is not None:
            self.algorithm = parse_hash_algorithm(algorithm)
        if extensions is not None:
            self.extensions.update(extensions)

    def update_ca_overrides(self, cn_in_san=None, add_crl_url=None, add_ocsp_url=None, add_issuer_url=None):
        if cn_in_san is not None:
            self.cn_in_san = cn_in_san
        if add_crl_url is not None:
            self.add_crl_url = add_crl_url
        if add_ocsp_url is not None:
            self.add_ocsp_url = add_ocsp_url
        if add_issuer_url is not None:
            self.add_issuer_url = add_issuer_url

    def update_san_from_cn(self):
        if self.cn_in_san is False or not self.subject.get('CN'):
            return

        try:
            cn = parse_general_name(self.subject['CN'])
        except idna.IDNAError:
            raise ValueError('%s: Could not parse CommonName as subjectAlternativeName.' % self.subject['CN'])

        self.extensions.setdefault(SubjectAlternativeName.key, SubjectAlternativeName({}))
        if cn not in self.extensions[SubjectAlternativeName.key]:
            self.extensions[SubjectAlternativeName.key].append(cn)


def get_profile(name=None):
    if name is None:
        name = ca_settings.CA_DEFAULT_PROFILE
    return Profile(name, **ca_settings.CA_PROFILES[name])


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
