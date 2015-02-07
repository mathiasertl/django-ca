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

import uuid

from datetime import datetime
from datetime import timedelta

from OpenSSL import crypto

from django.conf import settings
from django.db import models

from ca.utils import format_date


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
        cn = dict(subject.get_components()).get('CN')
        if cn is None:
            raise Exception('CSR has no CommonName!')

        # load CA key and cert
        with open(settings.CA_KEY) as ca_key:
            issuerKey = crypto.load_privatekey(crypto.FILETYPE_PEM, ca_key.read())
        with open(settings.CA_CRT) as ca_crt:
            issuerPub = crypto.load_certificate(crypto.FILETYPE_PEM, ca_crt.read())

        # compute notAfter info
        expires = datetime.today() + timedelta(days=days + 1)
        expires = expires.replace(hour=0, minute=0, second=0, microsecond=0)

        # create signed certificate
        cert = crypto.X509()
        cert.set_serial_number(uuid.uuid4().int)
        cert.set_notBefore(format_date(datetime.utcnow()))
        cert.set_notAfter(format_date(expires))
        cert.set_issuer(issuerPub.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())

        # collect any extension
        extensions = []

        # add subjectAltName if given:
        if subjectAltNames:
            subjData = str(','.join(['DNS:%s' % n for n in subjectAltNames]))
            ext = crypto.X509Extension(str('subjectAltName'), 0, subjData)
            extensions.append(ext)

        # set CRL distribution points:
        if settings.CA_CRL_DISTRIBUTION_POINTS:
            value = ','.join(['URI:%s' % uri for uri in settings.CA_CRL_DISTRIBUTION_POINTS])
            extensions.append(crypto.X509Extension(str('crlDistributionPoints'), 0, str(value)))

        # Add issuerAltName
        if settings.CA_ISSUER_ALT_NAME:
            alt_name = 'URI:%s' % settings.CA_ISSUER_ALT_NAME
            extensions.append(crypto.X509Extension(str('issuerAltName'), 0, str(alt_name)))

        # Add authorityInfoAccess
        auth_info_access = []
        if settings.CA_OCSP:
            auth_info_access.append('OCSP;URI:%s' % settings.CA_OCSP)
        if settings.CA_ISSUER:
            auth_info_access.append('caIssuers;URI:%s' % settings.CA_ISSUER)
        if auth_info_access:
            auth_info_access = str(','.join(auth_info_access))
            extensions.append(crypto.X509Extension(str('authorityInfoAccess'), 0, auth_info_access))

        # add basicConstraints, keyUsage and extendedKeyUsage
        extensions.append(crypto.X509Extension(str('basicConstraints'), 0, str('CA:FALSE')))
        extensions.append(crypto.X509Extension(str('keyUsage'), 0, str(','.join(key_usage))))
        extensions.append(crypto.X509Extension(str('extendedKeyUsage'), 0,
                                               str(','.join(ext_key_usage))))
        extensions.append(crypto.X509Extension(str('subjectKeyIdentifier'), 0, str('hash'),
                                               subject=cert))
        extensions.append(crypto.X509Extension(str('authorityKeyIdentifier'), 0,
                                               str('keyid,issuer'), issuer=issuerPub))


        cert.add_extensions(extensions)

        # finally sign the certificate:
        cert.sign(issuerKey, algorithm)

        # create database object
        crt = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        obj = self.create(csr=csr, pub=crt, cn=cn, expires=expires)

        # add watchers:
        if watchers:
            obj.watchers.add(*watchers)

        return obj
