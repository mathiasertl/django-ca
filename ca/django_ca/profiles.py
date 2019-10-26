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

from cryptography.hazmat.backends import default_backend

from . import ca_settings
from .extensions import KEY_TO_EXTENSION
from .extensions import AuthorityInformationAccess
from .extensions import AuthorityKeyIdentifier
from .extensions import BasicConstraints
from .extensions import CRLDistributionPoints
from .extensions import DistributionPoint
from .extensions import ExtendedKeyUsage
from .extensions import Extension
from .extensions import IssuerAlternativeName
from .extensions import KeyUsage
from .extensions import OCSPNoCheck
from .extensions import SubjectAlternativeName
from .extensions import TLSFeature
from .subject import Subject
from .subject import default_subject
from .utils import get_cert_builder
from .utils import get_default_subject
from .utils import parse_general_name
from .utils import parse_hash_algorithm
from .utils import shlex_split


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
                 issuer_name=None, description='',
                 add_crl_url=True, add_ocsp_url=True, add_issuer_url=True, add_issuer_alternative_name=True,
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
        self.add_issuer_alternative_name = add_issuer_alternative_name
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

        # set some defaults
        self.extensions.setdefault(BasicConstraints.key, BasicConstraints({'value': {'ca': False}}))

    def __repr__(self):
        return '<Profile: %r>' % self.name

    def __str__(self):
        return repr(self)

    def copy(self):
        """Create a deep copy of this profile."""

        return deepcopy(self)

    def create_cert(self, ca, csr, subject=None, expires=None, algorithm=None, extensions=None,
                    cn_in_san=None, add_crl_url=None, add_ocsp_url=None, add_issuer_url=None,
                    add_issuer_alternative_name=None, ca_password=None):
        """Create a x509 certificate based on this profile, the passed CA and input parameters.

        This function is the core function used to create x509 certificates. In it's simplest form, you only
        need to pass a ca, a csr and a subject to get a valid certificate::

            >>> profile = get_profile('webserver')
            >>> cert = profile.create_cert(ca, csr, '/CN=example.com')
            <Certificate(subject=<Name(CN=example.com)>, ...)>

        The function will add CRL, OCSP, Issuer and IssuerAlternativeName URLs based on the CA if the profile
        has the *add_crl_url*, *add_ocsp_url* and *add_issuer_url* and *add_issuer_alternative_name* values
        set. Parameters to this function with the same name allow you override this behaviour.

        The function allows you to override profile values using the *expires* and *algorithm* values. You can
        pass additional *extensions* as a list, which will override any extensions from the profile, but the
        CA passed will append to these extensions unless the *add_...* values are ``False``.

        Parameters
        ----------

        ca : :py:class:`~django_ca.models.CertificateAuthority`
            The CA to sign the certificate with.
        csr : str or :py:class:`~cg:cryptography.x509.CertificateSigningRequest`
            The CSR for the certificate.
        subject : dict or str or :py:class:`~django_ca.subject.Subject`
            Update the subject string, e.g. ``"/CN=example.com"`` or ``Subject("/CN=example.com")``. The
            values from the passed subject will update the profiles subject.
        expires : timedelta, optional
            Override when this certificate will expire.
        algorithm : str or :py:class:`~cg:cryptography.hazmat.primitives.hashes.HashAlgorithm`, optional
            Override the hash algorithm used when signing the certificate, passed to
            :py:func:`~django_ca.utils.parse_hash_algorithm`.
        extensions : list of :py:class:`~django_ca.extensions.Extension`
            List of additional extensions to set for the certificate. Note that values from the CA might
            update the passed extensions: For example, if you pass an
            :py:class:`~django_ca.extensions.IssuerAlternativeName` extension, *add_issuer_alternative_name*
            is ``True`` and the passed CA has an IssuerAlternativeName set, that value will be appended to the
            extension you pass here.
        cn_in_san : bool, optional
            Override if the CommonName should be added as an SubjectAlternativeName. If not passed, the value
            set in the profile is used.
        add_crl_url : bool, optional
            Override if any CRL URLs from the CA should be added to the CA. If not passed, the value set in
            the profile is used.
        add_ocsp_url : bool, optional
            Override if any OCSP URLs from the CA should be added to the CA. If not passed, the value set in
            the profile is used.
        add_issuer_url : bool, optional
            Override if any Issuer URLs from the CA should be added to the CA. If not passed, the value set in
            the profile is used.
        add_issuer_alternative_name : bool, optional
            Override if any IssuerAlternativeNames from the CA should be added to the CA. If not passed, the
            value set in the profile is used.
        ca_password: bytes or str, optional
            The password to the private key of the CA.

        Returns
        -------

        cryptography.x509.Certificate
            The signed certificate.
        """

        # Compute default values
        if extensions is None:
            extensions = {}
        else:
            extensions = {e.key: e for e in extensions}

        # Get overrides values from profile if not passed as parameter
        if cn_in_san is not None:
            cn_in_san = self.cn_in_san
        if add_crl_url is not None:
            add_crl_url = self.add_crl_url
        if add_ocsp_url is not None:
            add_ocsp_url = self.add_ocsp_url
        if add_issuer_url is not None:
            add_issuer_url = self.add_issuer_url
        if add_issuer_alternative_name is not None:
            add_issuer_alternative_name = self.add_issuer_alternative_name

        cert_extensions = deepcopy(self.extensions)
        cert_subject = deepcopy(self.subject)

        for extension in extensions:
            cert_extensions[extension.key] = extension

        issuer_name = self.update_from_ca(
            ca, cert_extensions, add_crl_url=add_crl_url, add_ocsp_url=add_ocsp_url,
            add_issuer_url=add_issuer_url, add_issuer_alternative_name=add_issuer_alternative_name)

        if not isinstance(subject, Subject):
            subject = Subject(subject)  # NOTE: also accepts None
        cert_subject.update(subject)

        if expires is None:
            expires = self.expires
        if algorithm is None:
            algorithm = self.algorithm
        else:
            algorithm = parse_hash_algorithm(self.algorithm)

        # Finally, update SAN with the current CN, if set and requested
        self.update_san_from_cn(cn_in_san, subject, extensions)
        # TODO: fail if there is no CN and no SAN

        # TODO: send pre_sign signal

        public_key = csr.public_key()

        builder = get_cert_builder(expires)
        builder = builder.public_key(public_key)
        builder = builder.issuer_name(issuer_name)
        builder = builder.subject_name(subject.name)

        for key, extension in cert_extensions.items():
            if not isinstance(extension, Extension):
                extension = KEY_TO_EXTENSION[key](extension)

            builder = builder.add_extension(**extension.for_builder())

        cert = builder.sign(private_key=ca.key(ca_password), algorithm=algorithm, backend=default_backend())
        return cert

    def update_from_ca(self, ca, extensions, add_crl_url=None, add_ocsp_url=None, add_issuer_url=None,
                       add_issuer_alternative_name=None):
        """Update data from the given CA.

        * Sets the AuthorityKeyIdentifier extension
        * Sets the OCSP url if add_ocsp_url is True
        * Sets a CRL URL if add_crl_url is True
        * Adds an IssuerAlternativeName if add_issuer_alternative_name is True

        """
        extensions.setdefault(AuthorityKeyIdentifier.key, ca.get_authority_key_identifier_extension())

        if add_crl_url is not False and ca.crl_url:
            extensions.setdefault(CRLDistributionPoints.key, CRLDistributionPoints({}))
            extensions[CRLDistributionPoints.key].value.append(DistributionPoint({
                'full_name': [url.strip() for url in ca.crl_url.split()],
            }))

        if add_ocsp_url is not False and ca.ocsp_url:
            extensions.setdefault(AuthorityInformationAccess.key, AuthorityInformationAccess({}))
            extensions[AuthorityInformationAccess.key].value['ocsp'].append(parse_general_name(ca.ocsp_url))

        if add_issuer_url is not False and ca.issuer_url:
            extensions.setdefault(AuthorityInformationAccess.key, AuthorityInformationAccess({}))
            extensions[AuthorityInformationAccess.key].value['issuers'].append(
                parse_general_name(ca.issuer_url)
            )
        if add_issuer_alternative_name is not False and ca.issuer_alt_name:
            extensions.set_default(IssuerAlternativeName.key, IssuerAlternativeName({}))
            extensions[IssuerAlternativeName.key].extend(shlex_split(ca.issuer_alt_name, ','))

        if self.issuer_name:
            return self.issuer_name.name
        else:
            return ca.x509.subject

    def update_san_from_cn(self, cn_in_san, subject, extensions):
        if cn_in_san is False or not subject.get('CN'):
            return

        try:
            cn = parse_general_name(subject['CN'])
        except idna.IDNAError:
            raise ValueError('%s: Could not parse CommonName as subjectAlternativeName.' % subject['CN'])

        extensions.setdefault(SubjectAlternativeName.key, SubjectAlternativeName({}))
        if cn not in extensions[SubjectAlternativeName.key]:
            extensions[SubjectAlternativeName.key].append(cn)


def get_profile(name=None):  # pragma: no cover
    if name is None:
        name = ca_settings.CA_DEFAULT_PROFILE
    return Profile(name, **ca_settings.CA_PROFILES[name])


def get_cert_profile_kwargs(name=None):
    """Get kwargs suitable for get_cert X509 keyword arguments from the given profile."""

    if name is None:
        name = ca_settings.CA_DEFAULT_PROFILE

    profile = deepcopy(ca_settings.CA_PROFILES[name])
    profile.setdefault('extensions', {})
    kwargs = {
        'cn_in_san': profile['cn_in_san'],
        'subject': get_default_subject(name=name),
    }

    key_usage = profile.get('keyUsage', profile['extensions'].get(KeyUsage.key))
    if key_usage and key_usage.get('value'):
        kwargs['key_usage'] = KeyUsage(key_usage)
    ext_key_usage = profile.get('extendedKeyUsage', profile['extensions'].get(ExtendedKeyUsage.key))
    if ext_key_usage and ext_key_usage.get('value'):
        kwargs['extended_key_usage'] = ExtendedKeyUsage(ext_key_usage)
    tls_feature = profile.get('TLSFeature')
    if tls_feature and tls_feature.get('value', profile['extensions'].get(TLSFeature.key)):
        kwargs['tls_feature'] = TLSFeature(tls_feature)
    if profile.get('ocsp_no_check'):
        kwargs['ocsp_no_check'] = profile['ocsp_no_check']
    elif OCSPNoCheck.key in profile['extensions'] and profile['extensions'].get(OCSPNoCheck.key) is not False:
        kwargs['ocsp_no_check'] = True

    return kwargs
