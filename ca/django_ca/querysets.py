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

from OpenSSL import crypto

from django.db import models
from django.db.models import Q
from django.utils import timezone

from .utils import get_cert_subject
from .utils import get_basic_cert
from .utils import is_power2
from . import ca_settings


class CertificateAuthorityQuerySet(models.QuerySet):
    def init(self, name, key_size, key_type, algorithm, expires, parent, pathlen, subject,
             issuer_url=None, issuer_alt_name=None, crl_url=None, ocsp_url=None, password=None):
        """Create a Certificate Authority."""

        # NOTE: This is already verified by KeySizeAction, so none of these checks should ever be
        #       True in the real world. None the less they are here as a safety precaution.
        if not is_power2(key_size):
            raise RuntimeError("%s: Key size must be a power of two." % key_size)
        elif key_size < ca_settings.CA_MIN_KEY_SIZE:
            raise RuntimeError("%s: Key size must be least %s bits."
                               % (key_size, ca_settings.CA_MIN_KEY_SIZE))

        private_key = crypto.PKey()
        private_key.generate_key(getattr(crypto, 'TYPE_%s' % key_type), key_size)

        # set basic properties
        cert = get_basic_cert(expires)
        for key, value in get_cert_subject(subject):
            setattr(cert.get_subject(), key, bytes(value, 'utf-8'))
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(private_key)

        # sign the certificate
        if parent is None:
            cert.sign(private_key, algorithm)
        else:
            cert.sign(parent.key, algorithm)

        basicConstraints = 'CA:TRUE'
        if pathlen is not False:
            basicConstraints += ', pathlen:%s' % pathlen

        san = b'DNS:' + bytes(subject['CN'], 'utf-8')
        cert.add_extensions([
            crypto.X509Extension(b'basicConstraints', True, basicConstraints.encode('utf-8')),
            crypto.X509Extension(b'keyUsage', 0, b'keyCertSign,cRLSign'),
            crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=cert),
            crypto.X509Extension(b'subjectAltName', 0, san),
        ])

        if parent is None:
            authKeyId = crypto.X509Extension(b'authorityKeyIdentifier', False,
                                             b'keyid:always', issuer=cert)
        else:
            authKeyId = crypto.X509Extension(b'authorityKeyIdentifier', False,
                                             b'keyid,issuer', issuer=parent.x509)
        cert.add_extensions([authKeyId])

        if crl_url is not None:
            crl_url = '\n'.join(crl_url)

        # create certificate in database
        ca = self.model(name=name, issuer_url=issuer_url, issuer_alt_name=issuer_alt_name,
                        ocsp_url=ocsp_url, crl_url=crl_url, parent=parent)
        ca.x509 = cert
        ca.private_key_path = os.path.join(ca_settings.CA_DIR, '%s.key' % ca.serial)
        ca.save()

        dump_args = []
        if password is not None:  # pragma: no cover
            dump_args = ['des3', password]

        # write private key to file
        oldmask = os.umask(247)
        with open(ca.private_key_path, 'w') as key_file:
            key = crypto.dump_privatekey(crypto.FILETYPE_PEM, private_key, *dump_args)
            key_file.write(key.decode('utf-8'))
        os.umask(oldmask)

        return ca

    def enabled(self):
        return self.filter(enabled=True)


class CertificateQuerySet(models.QuerySet):
    def valid(self):
        """Return valid certificates."""

        return self.filter(revoked=False, expires__gt=timezone.now())

    def expired(self):
        """Returns expired certificates.

        Note that this method does not return revoked certificates that would otherwise be expired.
        """
        return self.filter(revoked=False, expires__lt=timezone.now())

    def revoked(self):
        """Return revoked certificates."""

        return self.filter(revoked=True)

    def get_by_serial_or_cn(self, identifier):
        return self.get(Q(serial=identifier) | Q(cn=identifier))
