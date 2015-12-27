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

from datetime import datetime
from datetime import timedelta

from OpenSSL import crypto

from django.conf import settings
from django.db import models

from .utils import get_cert


class CertificateManager(models.Manager):

    def from_csr(self, csr, subjectAltNames=None, key_usage=None, ext_key_usage=None, days=730,
                 algorithm=None, watchers=None):
        # get algorithm used to sign certificate
        if algorithm is None:
            algorithm = settings.DIGEST_ALGORITHM
        if key_usage is None:
            key_usage = settings.CA_KEY_USAGE
        if ext_key_usage is None:
            ext_key_usage = settings.CA_EXT_KEY_USAGE

        # get certificate information
        req = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr)
        subject = req.get_subject()
        cn = dict(subject.get_components()).get(b'CN')
        if cn is None:
            raise Exception('CSR has no CommonName!')

        # load CA key and cert
        with open(settings.CA_KEY) as ca_key:
            issuerKey = crypto.load_privatekey(crypto.FILETYPE_PEM, ca_key.read())
        with open(settings.CA_CRT) as ca_crt:
            issuerPub = crypto.load_certificate(crypto.FILETYPE_PEM, ca_crt.read())

        # Compute notAfter info
        expires = datetime.today() + timedelta(days=days + 1)
        expires = expires.replace(hour=0, minute=0, second=0, microsecond=0)

        # Create signed certificate
        cert = get_cert(expires)
        cert.set_issuer(issuerPub.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())

        # Collect extensions
        extensions = [
            crypto.X509Extension(b'basicConstraints', 0, b'CA:FALSE'),
            crypto.X509Extension(b'keyUsage', 0, bytes(','.join(key_usage), 'utf-8')),
            crypto.X509Extension(b'extendedKeyUsage', 0, bytes(','.join(ext_key_usage), 'utf-8')),
            crypto.X509Extension(b'subjectKeyIdentifier', 0, b'hash', subject=cert),
            crypto.X509Extension(b'authorityKeyIdentifier', 0, b'keyid,issuer', issuer=issuerPub),
        ]

        # Add subjectAltNames, always also contains the CommonName
        subjectAltNames = get_subjectAltName(subjectAltNames, cn=cn)
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
        extensions.append(crypto.X509Extension(
            b'issuerAltName', 0, issuerAltName, issuer=issuerPub))

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
        cert.sign(issuerKey, algorithm)

        # Create database object
        crt = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        obj = self.create(csr=csr, pub=crt, cn=cn, expires=expires)

        # Add watchers:
        if watchers:
            obj.watchers.add(*watchers)

        return obj
