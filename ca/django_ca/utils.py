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

from datetime import datetime
from datetime import timedelta
from ipaddress import ip_address

from django.conf import settings

from OpenSSL import crypto

CA_KEY = None
CA_CRT = None


def format_date(date):
    """Format date as ASN1 GENERALIZEDTIME, as required by various fields."""
    return date.strftime('%Y%m%d%H%M%SZ')


def get_ca_key(reload=False):
    global CA_KEY
    if CA_KEY is None or reload is True:
        with open(settings.CA_KEY) as ca_key:
            CA_KEY = crypto.load_privatekey(crypto.FILETYPE_PEM, ca_key.read())
    return CA_KEY


def get_ca_crt(reload=False):
    global CA_CRT
    if CA_CRT is None or reload is True:
        with open(settings.CA_CRT) as ca_crt:
            CA_CRT = crypto.load_certificate(crypto.FILETYPE_PEM, ca_crt.read())
    return CA_CRT


def get_basic_cert(expires):
    not_before = format_date(datetime.utcnow() - timedelta(minutes=5))
    not_after = format_date(expires)

    cert = crypto.X509()
    cert.set_serial_number(uuid.uuid4().int)
    cert.set_notBefore(not_before.encode('utf-8'))
    cert.set_notAfter(not_after.encode('utf-8'))
    return cert


def get_cert(csr, csr_format=crypto.FILETYPE_PEM, expires=None, algorithm=None,
             basic_constraints='critical,CA:FALSE', subject_alt_names=None, key_usage=None,
             ext_key_usage=None):
    """Create a signed certificate from a CSR.

    Parameters
    ----------

    csr : str
        A valid CSR in PEM format. If none is given, `self.csr` will be used.
    csr_format : int, optional
        The format of the submitted CSR request. One of the OpenSSL.crypto.FILETYPE_*
        constants. The default is PEM.
    expires : int or datetime, optional
        When the certificate should expire. Either a datetime object or an int representing the
        number of days from now. The default is the CA_DEFAULT_EXPIRES setting.
    algorithm : {'sha512', 'sha256', ...}, optional
        Algorithm used to sign the certificate. The default is the DIGEST_ALGORITHM setting.
    basic_constraints : bool or None or str, optional
        Value for the `basicConstraints` X509 extension. May be `None` to omit it, a bool for
        `CA:TRUE` or `CA:FALSE`, or a str for a verbatim value. The default is `critical,CA:FALSE`.
    subject_alt_names : list of str, optional
    key_usage : list of str, optional
    ext_key_usage : list of str, optional

    Returns
    -------

    OpenSSL.crypto.X509
        The signed certificate.
    """
    req = crypto.load_certificate_request(csr_format, csr)

    # get algorithm used to sign certificate
    if not algorithm:
        algorithm = settings.DIGEST_ALGORITHM
    if not key_usage:
        key_usage = settings.CA_KEY_USAGE
    if not ext_key_usage:
        ext_key_usage = settings.CA_EXT_KEY_USAGE

    # Compute notAfter info
    if expires is None:
        expires = settings.CA_DEFAULT_EXPIRES
    if isinstance(expires, int):
        expires = datetime.today() + timedelta(days=expires + 1)
        expires = expires.replace(hour=0, minute=0, second=0, microsecond=0)

    # get CA key and cert
    ca_crt = get_ca_crt()
    ca_key = get_ca_key()

    # get the common name from the CSR
    cn = dict(req.get_subject().get_components()).get(b'CN')
    if cn is None:
        raise Exception('CSR has no CommonName!')
#    elif cn not in subject_alt_names:
#        # TODO: Replace CN with the first name in subject_alt_names
#        pass

    # Create signed certificate
    cert = get_basic_cert(expires)
    cert.set_issuer(ca_crt.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())

    extensions = [
        crypto.X509Extension(b'keyUsage', 0, bytes(','.join(key_usage), 'utf-8')),
        crypto.X509Extension(b'extendedKeyUsage', 0, bytes(','.join(ext_key_usage), 'utf-8')),
        crypto.X509Extension(b'subjectKeyIdentifier', 0, b'hash', subject=cert),
        crypto.X509Extension(b'authorityKeyIdentifier', 0, b'keyid,issuer', issuer=ca_crt),
    ]
    if basic_constraints is True:
        basic_constraints = 'CA:TRUE'
    elif basic_constraints is False:
        basic_constraints = 'CA:FALSE'

    if basic_constraints is not None:
        print('Setting basic_constraints: %s' % basic_constraints)
        extensions.append(crypto.X509Extension(b'basicConstraints', 0,
                                               bytes(basic_constraints, 'utf-8')))

    # Add subjectAltNames, always also contains the CommonName
    subjectAltNames = get_subjectAltName(subject_alt_names, cn=cn)
    extensions.append(crypto.X509Extension(b'subjectAltName', 0, subjectAltNames))

    # Set CRL distribution points:
    if settings.CA_CRL_DISTRIBUTION_POINTS:
        value = ','.join(['URI:%s' % uri for uri in settings.CA_CRL_DISTRIBUTION_POINTS])
        value = bytes(value, 'utf-8')
        extensions.append(crypto.X509Extension(b'crlDistributionPoints', 0, value))

    # Add issuerAltName
    if settings.CA_ISSUER_ALT_NAME:
        issuerAltName = bytes('URI:%s' % settings.CA_ISSUER_ALT_NAME, 'utf-8')
    else:
        issuerAltName = b'issuer:copy'
    extensions.append(crypto.X509Extension(b'issuerAltName', 0, issuerAltName, issuer=ca_crt))

    # Add authorityInfoAccess
    auth_info_access = []
    if settings.CA_OCSP:
        auth_info_access.append('OCSP;URI:%s' % settings.CA_OCSP)
    if settings.CA_ISSUER:
        auth_info_access.append('caIssuers;URI:%s' % settings.CA_ISSUER)
    if auth_info_access:
        auth_info_access = bytes(','.join(auth_info_access), 'utf-8')
        extensions.append(crypto.X509Extension(b'authorityInfoAccess', 0, auth_info_access))

    # Add collected extensions
    cert.add_extensions(extensions)

    # Finally sign the certificate:
    cert.sign(ca_key, algorithm)

    return cert


def get_subjectAltName(names, cn=None):
    """Compute the value of the subjectAltName extension based on the given list of names.

    The `cn` parameter, if provided, isprepended if not present in the list of names.

    This method supports the `IP`, `email`, `URI` and `DNS` options automatically, if you need a
    different option (or think the automatic parsing is wrong), give the full value verbatim (e.g.
    `otherName:1.2.3.4;UTF8:some other identifier`.
    """
    values = []
    names = sorted(set(names))
    if cn is not None and cn not in names:
        names.insert(0, cn)

    for name in names:
        if isinstance(name, bytes):
            name = name.decode('utf-8')

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
        elif ':' in name:
            values.append(name)
        else:
            values.append('DNS:%s' % name)

    return bytes(','.join(values), 'utf-8')
