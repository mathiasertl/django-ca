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

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509.oid import ExtensionOID

from django.db import models
from django.utils.encoding import force_bytes
from django.utils.encoding import force_text

from . import ca_settings
from .utils import EXTENDED_KEY_USAGE_MAPPING
from .utils import KEY_USAGE_MAPPING
from .utils import get_cert_builder
from .utils import is_power2
from .utils import parse_general_name
from .utils import x509_name


class CertificateManagerMixin(object):
    def get_common_extensions(self, issuer_url=None, crl_url=None, ocsp_url=None):
        extensions = []
        if crl_url:
            if isinstance(crl_url, str):
                crl_url = [url.strip() for url in crl_url.split()]
            urls = [x509.UniformResourceIdentifier(force_text(c)) for c in crl_url]
            dps = [x509.DistributionPoint(full_name=[c], relative_name=None, crl_issuer=None, reasons=None)
                   for c in urls]
            extensions.append((False, x509.CRLDistributionPoints(dps)))
        auth_info_access = []
        if ocsp_url:
            uri = x509.UniformResourceIdentifier(force_text(ocsp_url))
            auth_info_access.append(x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.OCSP, access_location=uri))
        if issuer_url:
            uri = x509.UniformResourceIdentifier(force_text(issuer_url))
            auth_info_access.append(x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.CA_ISSUERS, access_location=uri))
        if auth_info_access:
            extensions.append((False, x509.AuthorityInformationAccess(auth_info_access)))
        return extensions


class CertificateAuthorityManager(CertificateManagerMixin, models.Manager):
    def init(self, name, key_size, key_type, algorithm, expires, parent, subject, pathlen=None,
             issuer_url=None, issuer_alt_name=None, crl_url=None, ocsp_url=None,
             ca_issuer_url=None, ca_crl_url=None, ca_ocsp_url=None, name_constraints=None,
             password=None):
        # NOTE: This is already verified by KeySizeAction, so none of these checks should ever be
        #       True in the real world. None the less they are here as a safety precaution.
        if not is_power2(key_size):
            raise RuntimeError("%s: Key size must be a power of two." % key_size)
        elif key_size < ca_settings.CA_MIN_KEY_SIZE:
            raise RuntimeError("%s: Key size must be least %s bits."
                               % (key_size, ca_settings.CA_MIN_KEY_SIZE))

        if key_type == 'DSA':
            private_key = dsa.generate_private_key(key_size=key_size, backend=default_backend())
        else:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size,
                                                   backend=default_backend())
        public_key = private_key.public_key()
        subject = x509_name(subject)

        builder = get_cert_builder(expires)
        builder = builder.public_key(public_key)
        builder = builder.subject_name(subject)

        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=pathlen), critical=True)
        builder = builder.add_extension(x509.KeyUsage(
            key_cert_sign=True, crl_sign=True, digital_signature=False, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False, encipher_only=False,
            decipher_only=False), critical=True)

        subject_key_id = x509.SubjectKeyIdentifier.from_public_key(public_key)
        builder = builder.add_extension(subject_key_id, critical=False)

        if parent is None:
            builder = builder.issuer_name(subject)
            auth_key_id = x509.AuthorityKeyIdentifier(
                key_identifier=subject_key_id.digest, authority_cert_issuer=None,
                authority_cert_serial_number=None)
        else:
            builder = builder.issuer_name(parent.x509.subject)
            auth_key_id = parent.x509.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value

        builder = builder.add_extension(auth_key_id, critical=False)

        for critical, ext in self.get_common_extensions(ca_issuer_url, ca_crl_url, ca_ocsp_url):
            builder = builder.add_extension(ext, critical=critical)

        # TODO: pass separate lists maybe?
        if name_constraints:
            excluded = []
            permitted = []
            for constraint in name_constraints:
                typ, name = constraint.split(';', 1)
                parsed = parse_general_name(name)
                if typ == 'permitted':
                    permitted.append(parsed)
                else:
                    excluded.append(parsed)

            builder = builder.add_extension(x509.NameConstraints(
                permitted_subtrees=permitted, excluded_subtrees=excluded), critical=True)

        certificate = builder.sign(private_key=private_key, algorithm=algorithm, backend=default_backend())

        if crl_url is not None:
            crl_url = '\n'.join(crl_url)

        ca = self.model(name=name, issuer_url=issuer_url, issuer_alt_name=issuer_alt_name,
                        ocsp_url=ocsp_url, crl_url=crl_url, parent=parent)
        ca.x509 = certificate
        ca.private_key_path = os.path.join(ca_settings.CA_DIR, '%s.key' % ca.serial)
        ca.save()

        # write private key to file
        oldmask = os.umask(247)
        pem = private_key.private_bytes(encoding=Encoding.PEM,
                                        format=PrivateFormat.TraditionalOpenSSL,
                                        encryption_algorithm=serialization.NoEncryption())
        with open(ca.private_key_path, 'wb') as key_file:
            key_file.write(pem)
        os.umask(oldmask)

        return ca


class CertificateManager(CertificateManagerMixin, models.Manager):
    def init(self, ca, csr, expires, algorithm, subject=None, cn_in_san=True, csr_format='PEM',
             subjectAltName=None, keyUsage=None, extendedKeyUsage=None):
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
            When the certificate should expire (passed to :py:func:`get_cert_builder`).
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
        csr_format : {'PEM', 'DER'}, optional
            The format of the CSR. The default is ``'PEM'``.
        subjectAltName : list of str, optional
            A list of values for the subjectAltName extension. Values are passed to
            :py:func:`~django_ca.utils.parse_general_name`, see function documentation for how this value is
            parsed.
        keyUsage : tuple or None
            Value for the `keyUsage` X509 extension. See description for format details.
        extendedKeyUsage : tuple or None
            Value for the `extendedKeyUsage` X509 extension. See description for format details.

        Returns
        -------

        cryptography.x509.Certificate
            The signed certificate.
        """
        if subject is None:
            subject = {}
        if not subject.get('CN') and not subjectAltName:
            raise ValueError("Must name at least a CN or a subjectAltName.")

        if subjectAltName:
            subjectAltName = [parse_general_name(san) for san in subjectAltName]
        else:
            subjectAltName = []  # so we can append the CN if requested

        if not subject.get('CN'):  # use first SAN as CN if CN is not set
            subject['CN'] = subjectAltName[0].value
        elif cn_in_san and subject.get('CN'):  # add CN to SAN if cn_in_san is True (default)
            cn_name = parse_general_name(subject['CN'])
            if cn_name not in subjectAltName:
                subjectAltName.insert(0, cn_name)

        if csr_format == 'PEM':
            req = x509.load_pem_x509_csr(force_bytes(csr), default_backend())
        elif csr_format == 'DER':
            req = x509.load_der_x509_csr(force_bytes(csr), default_backend())
        else:
            raise ValueError('Unknown CSR format passed: %s' % csr_format)

        public_key = req.public_key()

        builder = get_cert_builder(expires)
        builder = builder.public_key(public_key)
        builder = builder.issuer_name(ca.x509.subject)

        builder = builder.subject_name(x509_name(subject))

        # Add extensions
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        builder = builder.add_extension(
            ca.x509.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value,
            critical=False)
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)

        for critical, ext in self.get_common_extensions(ca.issuer_url, ca.crl_url, ca.ocsp_url):
            builder = builder.add_extension(ext, critical=critical)

        if subjectAltName:
            builder = builder.add_extension(x509.SubjectAlternativeName(subjectAltName), critical=False)

        if keyUsage:
            critical, values = keyUsage
            params = {v: False for v in KEY_USAGE_MAPPING.values()}
            for value in [KEY_USAGE_MAPPING[k] for k in values.split(',')]:
                params[value] = True
            builder = builder.add_extension(x509.KeyUsage(**params), critical=critical)

        if extendedKeyUsage:
            critical, usages = extendedKeyUsage
            usages = [EXTENDED_KEY_USAGE_MAPPING[u] for u in usages.split(',')]
            builder = builder.add_extension(x509.ExtendedKeyUsage(usages), critical=critical)

        if ca.issuer_alt_name:
            builder = builder.add_extension(x509.IssuerAlternativeName(
                [parse_general_name(ca.issuer_alt_name)]), critical=False)

        return builder.sign(private_key=ca.key, algorithm=algorithm, backend=default_backend())
