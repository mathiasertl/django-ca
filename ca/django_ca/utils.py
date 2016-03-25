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

"""Central functions to load CA key and cert as PKey/X509 objects."""

import re
import uuid

from copy import deepcopy
from datetime import datetime
from datetime import timedelta
from ipaddress import ip_address

from django.core.serializers.json import DjangoJSONEncoder
from django.utils.encoding import force_text
from django.utils.functional import Promise
from django.utils.translation import ugettext_lazy as _

from OpenSSL import crypto

from django_ca import ca_settings


# Description strings for various X509 extensions, taken from "man x509v3_config".
EXTENDED_KEY_USAGE_DESC = _('Purposes for which the certificate public key can be used for.')
KEY_USAGE_DESC = _('Permitted key usages.')
SAN_OPTIONS_RE = '(email|URI|IP|DNS|RID|dirName|otherName):'
_datetime_format = '%Y%m%d%H%M%SZ'


class LazyEncoder(DjangoJSONEncoder):
    """Encoder that also encodes translated strings."""

    def default(self, obj):
        if isinstance(obj, Promise):
            return force_text(obj)
        return super(LazyEncoder, self).default(obj)


def parse_date(date):
    return datetime.strptime(date, _datetime_format)


def format_date(date):
    """Format date as ASN1 GENERALIZEDTIME, as required by various fields."""
    return date.strftime(_datetime_format)


def is_power2(num):
    """Return True if num is a power of 2."""
    return num != 0 and ((num & (num - 1)) == 0)


def multiline_url_validator(value):
    pass

def get_basic_cert(expires, now=None):
    """Get a basic X509 cert object.

    Parameters
    ----------

    expires : int
        When, in number of days from now, this certificate will expire.
    """
    if expires < 0:
        raise ValueError("Expires must not be negative.")

    if now is None:  # pragma: no cover
        now = datetime.utcnow()
    now = now.replace(second=0, microsecond=0)

    not_before = format_date(now)

    # make expires to a datetime
    expires = now + timedelta(days=expires + 1)
    expires = expires.replace(hour=0, minute=0, second=0, microsecond=0)

    not_after = format_date(expires)

    cert = crypto.X509()
    cert.set_serial_number(uuid.uuid4().int)
    cert.set_notBefore(not_before.encode('utf-8'))
    cert.set_notAfter(not_after.encode('utf-8'))
    return cert


def get_cert_profile_kwargs(name=None):
    """Get kwargs suitable for get_cert X509 keyword arguments from the given profile."""

    if name is None:
        name = ca_settings.CA_DEFAULT_PROFILE

    profile = deepcopy(ca_settings.CA_PROFILES[name])
    kwargs = {
        'cn_in_san': profile['cn_in_san'],
        'subject': profile['subject'],
    }
    for arg in ['keyUsage', 'extendedKeyUsage']:
        config = profile.get(arg)
        if config is None or not config.get('value'):
            continue

        critical = config.get('critical', 'True')
        if isinstance(config['value'], str):
            kwargs[arg] = (critical, bytes(config['value'], 'utf-8'))
        elif isinstance(config['value'], bytes):
            kwargs[arg] = (critical, config['value'])
        else:
            kwargs[arg] = (critical, bytes(','.join(config['value']), 'utf-8'))
    return kwargs


def get_cert(ca, csr, expires, algorithm, subject=None, cn_in_san=True,
             csr_format=crypto.FILETYPE_PEM, subjectAltName=None, keyUsage=None,
             extendedKeyUsage=None):
    """Create a signed certificate from a CSR.

    X509 extensions (`key_usage`, `ext_key_usage`) may either be None (in which case they are not
    added) or a tuple with the first value being a bool indicating if the value is critical and the
    second value being a byte-array indicating the extension value. Example::

        (True, b'value')

    Parameters
    ----------

    ca : django_ca.models.CertificateAuthority
        The certificate authority to sign the certificate with.
    csr : str
        A valid CSR in PEM format. If none is given, `self.csr` will be used.
    expires : int
        When the certificate should expire (passed to :py:func:`get_basic_cert`).
    algorithm : {'sha512', 'sha256', ...}
        Algorithm used to sign the certificate. The default is the CA_DIGEST_ALGORITHM setting.
    subject : dict, optional
        The Subject to use in the certificate.  The keys of this dict are the fields of an X509
        subject, that is `"C"`, `"ST"`, `"L"`, `"OU"` and `"CN"`. If ommited or if the value does
        not contain a `"CN"` key, the first value of the `subjectAltName` parameter is used as
        CommonName (and is obviously mandatory in this case).
    cn_in_san : bool, optional
        Wether the CommonName should also be included as subjectAlternativeName. The default is
        `True`, but the parameter is ignored if no CommonName is given. This is typically set to
        `False` when creating a client certificate, where the subjects CommonName has no meaningful
        value as subjectAltName.
    csr_format : int, optional
        The format of the submitted CSR request. One of the OpenSSL.crypto.FILETYPE_*
        constants. The default is PEM.
    subjectAltName : list of str, optional
        A list of values for the subjectAltName extension. Values are passed to
        `get_subjectAltName`, see function documentation for how this value is parsed.
    keyUsage : tuple or None
        Value for the `keyUsage` X509 extension. See description for format details.
    extendedKeyUsage : tuple or None
        Value for the `extendedKeyUsage` X509 extension. See description for format details.

    Returns
    -------

    OpenSSL.crypto.X509
        The signed certificate.
    """
    if subject is None:
        subject = {}
    if not subject.get('CN') and not subjectAltName:
        raise ValueError("Must at least cn or subjectAltName parameter.")

    req = crypto.load_certificate_request(csr_format, csr)

    # Process CommonName and subjectAltName extension.
    if subject.get('CN') is None:
        subject['CN'] = re.sub('^%s' % SAN_OPTIONS_RE, '', subjectAltName[0])
        subjectAltName = get_subjectAltName(subjectAltName)
    elif cn_in_san is True:
        if subjectAltName:
            subjectAltName = get_subjectAltName(subjectAltName, cn=subject['CN'])
        else:
            subjectAltName = get_subjectAltName([subject['CN']])

    # subjectAltName might still be None, in which case the extension is not added.
    elif subjectAltName:
        subjectAltName = get_subjectAltName(subjectAltName)

    # Create signed certificate
    cert = get_basic_cert(expires)
    cert.set_issuer(ca.x509.get_subject())
    for key, value in subject.items():
        setattr(cert.get_subject(), key, bytes(value, 'utf-8'))
    cert.set_pubkey(req.get_pubkey())

    extensions = [
        crypto.X509Extension(b'subjectKeyIdentifier', 0, b'hash', subject=cert),
        crypto.X509Extension(b'authorityKeyIdentifier', 0, b'keyid,issuer', issuer=ca.x509),
        crypto.X509Extension(b'basicConstraints', True, b'CA:FALSE'),
    ]

    if keyUsage is not None:
        extensions.append(crypto.X509Extension(b'keyUsage', *keyUsage))
    if extendedKeyUsage is not None:
        extensions.append(crypto.X509Extension(b'extendedKeyUsage', *extendedKeyUsage))

    # Add subjectAltNames, always also contains the CommonName
    if subjectAltName is not None:
        extensions.append(crypto.X509Extension(b'subjectAltName', 0, subjectAltName))

    # Set CRL distribution points:
    if ca_settings.CA_CRL_DISTRIBUTION_POINTS:
        value = ','.join(['URI:%s' % uri for uri in ca_settings.CA_CRL_DISTRIBUTION_POINTS])
        value = bytes(value, 'utf-8')
        extensions.append(crypto.X509Extension(b'crlDistributionPoints', 0, value))

    # Add issuerAltName
    if ca.issuer_alt_name:
        issuerAltName = bytes('URI:%s' % ca.issuer_alt_name, 'utf-8')
    else:
        issuerAltName = b'issuer:copy'
    extensions.append(crypto.X509Extension(b'issuerAltName', 0, issuerAltName, issuer=ca.x509))

    # Add authorityInfoAccess
    auth_info_access = []
    if ca_settings.CA_OCSP:
        auth_info_access.append('OCSP;URI:%s' % ca_settings.CA_OCSP)
    if ca_settings.CA_ISSUER:
        auth_info_access.append('caIssuers;URI:%s' % ca_settings.CA_ISSUER)
    if auth_info_access:
        auth_info_access = bytes(','.join(auth_info_access), 'utf-8')
        extensions.append(crypto.X509Extension(b'authorityInfoAccess', 0, auth_info_access))

    # Add collected extensions
    cert.add_extensions(extensions)

    # Finally sign the certificate:
    cert.sign(ca.key, algorithm)

    return cert


def get_subjectAltName(names, cn=None):
    """Compute the value of the subjectAltName extension based on the given list of names.

    The `cn` parameter, if provided, is prepended if not present in the list of names.

    This method supports the `IP`, `email`, `URI` and `DNS` options automatically, if you need a
    different option (or think the automatic parsing is wrong), give the full value verbatim (e.g.
    `otherName:1.2.3.4;UTF8:some other identifier`.
    """
    values = []
    names = sorted(set(names))

    for name in names:
        if not name:
            continue
        if isinstance(name, bytes):
            name = name.decode('utf-8')

        # Match any known literal values
        if re.match(SAN_OPTIONS_RE, name):
            values.append(name)
            continue

        try:
            ip_address(name)
            values.append('IP:%s' % name)
            continue
        except ValueError:
            pass

        if re.match('[a-z0-9]{2,}://', name):
            values.append('URI:%s' % name)
        elif '@' in name:
            values.append('email:%s' % name)
        else:
            values.append('DNS:%s' % name)

    if cn is not None:
        value = 'DNS:%s' % cn
        if value not in values:
            values.insert(0, value)

    return bytes(','.join(values), 'utf-8')
