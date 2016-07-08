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
import re

from OpenSSL import crypto

from django.db import models
from django.utils.encoding import force_bytes

from . import ca_settings
from .utils import SAN_OPTIONS_RE
from .utils import get_basic_cert
from .utils import sort_subject_dict
from .utils import get_subjectAltName
from .utils import is_power2


class CertificateAuthorityManager(models.Manager):
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
        for key, value in sort_subject_dict(subject):
            setattr(cert.get_subject(), key, force_bytes(value))
        cert.set_pubkey(private_key)

        basicConstraints = 'CA:TRUE'
        if pathlen is not False:
            basicConstraints += ', pathlen:%s' % pathlen

        san = force_bytes('DNS:%s' % subject['CN'])
        cert.add_extensions([
            crypto.X509Extension(b'basicConstraints', True, basicConstraints.encode('utf-8')),
            crypto.X509Extension(b'keyUsage', 0, b'keyCertSign,cRLSign'),
            crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=cert),
            crypto.X509Extension(b'subjectAltName', 0, san),
        ])

        if parent is None:
            cert.set_issuer(cert.get_subject())
            authKeyId = crypto.X509Extension(b'authorityKeyIdentifier', False,
                                             b'keyid:always', issuer=cert)
        else:
            cert.set_issuer(parent.x509.get_subject())
            authKeyId = crypto.X509Extension(b'authorityKeyIdentifier', False,
                                             b'keyid,issuer', issuer=parent.x509)
        cert.add_extensions([authKeyId])

        # sign the certificate
        if parent is None:
            cert.sign(private_key, algorithm)
        else:
            cert.sign(parent.key, algorithm)

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


class CertificateManager(models.Manager):
    def init(self, ca, csr, expires, algorithm, subject=None, cn_in_san=True,
             csr_format=crypto.FILETYPE_PEM, subjectAltName=None, keyUsage=None,
                 extendedKeyUsage=None):
        """Create a signed certificate from a CSR.

        X509 extensions (`key_usage`, `ext_key_usage`) may either be None (in which case they are
        not added) or a tuple with the first value being a bool indicating if the value is critical
        and the second value being a byte-array indicating the extension value. Example::

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
            subject, that is `"C"`, `"ST"`, `"L"`, `"OU"` and `"CN"`. If ommited or if the value
            does not contain a `"CN"` key, the first value of the `subjectAltName` parameter is
            used as CommonName (and is obviously mandatory in this case).
        cn_in_san : bool, optional
            Wether the CommonName should also be included as subjectAlternativeName. The default is
            `True`, but the parameter is ignored if no CommonName is given. This is typically set
            to `False` when creating a client certificate, where the subjects CommonName has no
            meaningful value as subjectAltName.
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
        for key, value in sort_subject_dict(subject):
            setattr(cert.get_subject(), key, force_bytes(value))
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
        if subjectAltName:
            extensions.append(crypto.X509Extension(b'subjectAltName', 0, subjectAltName))

        # Set CRL distribution points:
        if ca.crl_url:
            crl_urls = [url.strip() for url in ca.crl_url.split()]
            value = force_bytes(','.join(['URI:%s' % uri for uri in crl_urls]))
            extensions.append(crypto.X509Extension(b'crlDistributionPoints', 0, value))

        # Add issuerAltName
        if ca.issuer_alt_name:
            issuerAltName = force_bytes('URI:%s' % ca.issuer_alt_name)
        else:
            issuerAltName = b'issuer:copy'
        extensions.append(crypto.X509Extension(b'issuerAltName', 0, issuerAltName, issuer=ca.x509))

        # Add authorityInfoAccess
        auth_info_access = []
        if ca.ocsp_url:
            auth_info_access.append('OCSP;URI:%s' % ca.ocsp_url)
        if ca.issuer_url:
            auth_info_access.append('caIssuers;URI:%s' % ca.issuer_url)
        if auth_info_access:
            auth_info_access = force_bytes(','.join(auth_info_access))
            extensions.append(crypto.X509Extension(b'authorityInfoAccess', 0, auth_info_access))

        # Add collected extensions
        cert.add_extensions(extensions)

        # Finally sign the certificate:
        cert.sign(ca.key, str(algorithm))  # str() to force py2 unicode to str

        return cert
