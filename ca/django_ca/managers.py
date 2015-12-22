# -*- coding: utf-8 -*-
#
# This file is part of fsinf-certificate-authority (https://github.com/fsinf/certificate-authority).
#
# fsinf-certificate-authority is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software Foundation, either
# version 3 of the License, or (at your option) any later version.
#
# fsinf-certificate-authority is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
# PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# fsinf-certificate-authority.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import unicode_literals

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

        # Add subjectAltName if given:
        if subjectAltNames:
            subjData = str(','.join(['DNS:%s' % n for n in subjectAltNames]))
            ext = crypto.X509Extension(str('subjectAltName'), 0, subjData)
            extensions.append(ext)

        # Set CRL distribution points:
        if settings.CA_CRL_DISTRIBUTION_POINTS:
            value = ','.join(['URI:%s' % uri for uri in settings.CA_CRL_DISTRIBUTION_POINTS])
            extensions.append(crypto.X509Extension(str('crlDistributionPoints'), 0, str(value)))

        # Add issuerAltName
        if settings.CA_ISSUER_ALT_NAME:
            issuerAltName = str('URI:%s' % settings.CA_ISSUER_ALT_NAME)
        else:
            issuerAltName = str('issuer:copy')
        extensions.append(crypto.X509Extension(
            b'issuerAltName', 0, issuerAltName.encode('utf-8'), issuer=issuerPub))

        # Add authorityInfoAccess
        auth_info_access = []
        if settings.CA_OCSP:
            auth_info_access.append('OCSP;URI:%s' % settings.CA_OCSP)
        if settings.CA_ISSUER:
            auth_info_access.append('caIssuers;URI:%s' % settings.CA_ISSUER)
        if auth_info_access:
            auth_info_access = str(','.join(auth_info_access))
            extensions.append(crypto.X509Extension(str('authorityInfoAccess'), 0, auth_info_access))

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
