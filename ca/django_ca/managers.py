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

import idna

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509.oid import ExtensionOID

from django.db import models
from django.utils import six
from django.utils.encoding import force_bytes
from django.utils.encoding import force_text

from . import ca_settings
from .signals import post_create_ca
from .signals import post_issue_cert
from .signals import pre_create_ca
from .signals import pre_issue_cert
from .subject import Subject
from .utils import get_cert_builder
from .utils import is_power2
from .utils import parse_general_name
from .utils import parse_key_curve
from .utils import write_private_file


class CertificateManagerMixin(object):
    def get_common_extensions(self, issuer_url=None, crl_url=None, ocsp_url=None):
        extensions = []
        if crl_url:
            if isinstance(crl_url, six.string_types):
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
    def init(self, name, algorithm, expires, parent, subject, pathlen=None,
             issuer_url=None, issuer_alt_name=None, crl_url=None, ocsp_url=None,
             ca_issuer_url=None, ca_crl_url=None, ca_ocsp_url=None, name_constraints=None,
             password=None, parent_password=None, ecc_curve=None, key_type='RSA', key_size=None):
        """Create a new certificate authority.

        Parameters
        ----------

        name : str
            The name of the CA. This can be a human-readable string and is used for administrative purposes
            only.
        algorithm : :py:class:`~cryptography:cryptography.hazmat.primitives.hashes.HashAlgorithm`
            Hash algorithm used when signing the certificate. Must be an instance of
            :py:class:`~cryptography:cryptography.hazmat.primitives.hashes.HashAlgorithm`, e.g.
            :py:class:`~cryptography:cryptography.hazmat.primitives.hashes.SHA512`.
        expires : datetime
            Datetime for when this certificate expires.
        parent : :py:class:`~django_ca.models.CertificateAuthority`, optional
            Parent certificate authority for the new CA. This means that this CA will be an intermediate
            authority.
        subject : :py:class:`~django_ca.subject.Subject`
            Subject string, e.g. ``Subject("/CN=example.com")``.
        pathlen : int, optional
        password : bytes, optional
            Password to encrypt the private key with.
        parent_password : bytes, optional
            Password that the private key of the parent CA is encrypted with.
        ecc_curve : str or EllipticCurve, optional
            The elliptic curve to use for ECC type keys, passed verbatim to
            :py:func:`~django_ca.utils.parse_key_curve`.
        key_type: str, optional
            The type of private key to generate, must be one of ``"RSA"``, ``"DSA"`` or ``"ECC"``, with
            ``"RSA"`` being the default.
        key_size : int, optional
            Integer specifying the key size, must be a power of two (e.g. 2048, 4096, ...) unused if
            ``key_type="ECC"`` but required otherwise.

        Raises
        ------

        PermissionError
            If the private key file cannot be written to disk.
        """
        # NOTE: This is already verified by KeySizeAction, so none of these checks should ever be
        #       True in the real world. None the less they are here as a safety precaution.
        if key_type != 'ECC':
            if not is_power2(key_size):
                raise RuntimeError("%s: Key size must be a power of two." % key_size)
            elif key_size < ca_settings.CA_MIN_KEY_SIZE:
                raise RuntimeError("%s: Key size must be least %s bits."
                                   % (key_size, ca_settings.CA_MIN_KEY_SIZE))

        pre_create_ca.send(
            sender=self.model, name=name, key_size=key_size, key_type=key_type, algorithm=algorithm,
            expires=expires, parent=parent, subject=subject, pathlen=pathlen, issuer_url=issuer_url,
            issuer_alt_name=issuer_alt_name, crl_url=crl_url, ocsp_url=ocsp_url, ca_issuer_url=ca_issuer_url,
            ca_crl_url=ca_crl_url, ca_ocsp_url=ca_ocsp_url, name_constraints=name_constraints,
            password=password, parent_password=parent_password)

        if key_type == 'DSA':
            private_key = dsa.generate_private_key(key_size=key_size, backend=default_backend())
        elif key_type == 'ECC':
            ecc_curve = parse_key_curve(ecc_curve)
            private_key = ec.generate_private_key(ecc_curve, default_backend())
        else:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size,
                                                   backend=default_backend())
        public_key = private_key.public_key()

        builder = get_cert_builder(expires)
        builder = builder.public_key(public_key)
        subject = subject.name

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
            private_sign_key = private_key
            auth_key_id = x509.AuthorityKeyIdentifier(
                key_identifier=subject_key_id.digest, authority_cert_issuer=None,
                authority_cert_serial_number=None)
        else:
            builder = builder.issuer_name(parent.x509.subject)
            private_sign_key = parent.key(parent_password)
            auth_key_id = parent.x509.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value

        builder = builder.add_extension(auth_key_id, critical=False)

        for critical, ext in self.get_common_extensions(ca_issuer_url, ca_crl_url, ca_ocsp_url):
            builder = builder.add_extension(ext, critical=critical)

        if name_constraints:
            excluded = []
            permitted = []
            for constraint in name_constraints:
                typ, name = constraint.split(',', 1)
                parsed = parse_general_name(name)
                if typ == 'permitted':
                    permitted.append(parsed)
                else:
                    excluded.append(parsed)

            builder = builder.add_extension(x509.NameConstraints(
                permitted_subtrees=permitted, excluded_subtrees=excluded), critical=True)

        certificate = builder.sign(private_key=private_sign_key, algorithm=algorithm,
                                   backend=default_backend())

        if crl_url is not None:
            crl_url = '\n'.join(crl_url)

        ca = self.model(name=name, issuer_url=issuer_url, issuer_alt_name=issuer_alt_name,
                        ocsp_url=ocsp_url, crl_url=crl_url, parent=parent)
        ca.x509 = certificate
        ca.private_key_path = os.path.join(ca_settings.CA_DIR, '%s.key' % ca.serial)
        ca.save()

        if password is None:
            encryption = serialization.NoEncryption()
        else:
            encryption = serialization.BestAvailableEncryption(password)

        pem = private_key.private_bytes(encoding=Encoding.PEM,
                                        format=PrivateFormat.PKCS8,
                                        encryption_algorithm=encryption)

        # write private key to file
        write_private_file(ca.private_key_path, pem)

        post_create_ca.send(sender=self.model, ca=ca)
        return ca


class CertificateManager(CertificateManagerMixin, models.Manager):
    def sign_cert(self, ca, csr, expires, algorithm, subject=None, cn_in_san=True, csr_format=Encoding.PEM,
                  subjectAltName=None, key_usage=None, extended_key_usage=None, tls_feature=None,
                  password=None):
        """Create a signed certificate from a CSR.

        **PLEASE NOTE:** This function creates the raw certificate and is usually not invoked directly. It is
        called by :py:func:`Certificate.objects.init() <django_ca.managers.CertificateManager.init>`, which
        passes along all parameters unchanged and saves the raw certificate to the database.

        Parameters
        ----------

        ca : :py:class:`~django_ca.models.CertificateAuthority`
            The certificate authority to sign the certificate with.
        csr : str
            A valid CSR. The format is given by the ``csr_format`` parameter.
        expires : int
            When the certificate should expire (passed to :py:func:`~django_ca.utils.get_cert_builder`).
        algorithm : {'sha512', 'sha256', ...}
            Algorithm used to sign the certificate. The default is the CA_DIGEST_ALGORITHM setting.
        subject : :py:class:`~django_ca.subject.Subject`, optional
            The Subject to use in the certificate. If this value is not passed or if the value does not
            contain a CommonName, the first value of the ``subjectAltName`` parameter is used as CommonName.
        cn_in_san : bool, optional
            Wether the CommonName should also be included as subjectAlternativeName. The default is
            ``True``, but the parameter is ignored if no CommonName is given. This is typically set
            to ``False`` when creating a client certificate, where the subjects CommonName has no
            meaningful value as subjectAltName.
        csr_format : :py:class:`~cryptography:cryptography.hazmat.primitives.serialization.Encoding`, optional
            The format of the CSR. The default is ``PEM``.
        subjectAltName : list of str, optional
            A list of values for the subjectAltName extension. Values are passed to
            :py:func:`~django_ca.utils.parse_general_name`, see function documentation for how this value is
            parsed.
        key_usage : :py:class:`~django_ca.extensions.KeyUsage`, optional
            Value for the ``keyUsage`` X509 extension.
        extended_key_usage : :py:class:`~django_ca.extensions.ExtendedKeyUsage`, optional
            Value for the ``extendedKeyUsage`` X509 extension.
        tls_feature : :py:class:`~django_ca.extensions.TLSFeature`, optional
            Value for the ``TLSFeature`` X509 extension.
        password : bytes, optional
            Password used to load the private key of the certificate authority. If not passed, the private key
            is assumed to be unencrypted.

        Returns
        -------

        cryptography.x509.Certificate
            The signed certificate.
        """
        if subject is None:
            subject = Subject()

        if 'CN' not in subject and not subjectAltName:
            raise ValueError("Must name at least a CN or a subjectAltName.")

        if subjectAltName:
            subjectAltName = [parse_general_name(san) for san in subjectAltName]
        else:
            subjectAltName = []  # so we can append the CN if requested

        # use first SAN as CN if CN is not set
        if 'CN' not in subject:
            subject['CN'] = subjectAltName[0].value
        elif cn_in_san and 'CN' in subject:  # add CN to SAN if cn_in_san is True (default)
            try:
                cn_name = parse_general_name(subject['CN'])
            except idna.IDNAError:
                raise ValueError('%s: Could not parse CommonName as subjectAltName.' % subject['CN'])
            else:
                if cn_name not in subjectAltName:
                    subjectAltName.insert(0, cn_name)

        if csr_format == Encoding.PEM:
            req = x509.load_pem_x509_csr(force_bytes(csr), default_backend())
        elif csr_format == Encoding.DER:
            req = x509.load_der_x509_csr(force_bytes(csr), default_backend())
        else:
            raise ValueError('Unknown CSR format passed: %s' % csr_format)

        public_key = req.public_key()

        builder = get_cert_builder(expires)
        builder = builder.public_key(public_key)
        builder = builder.issuer_name(ca.x509.subject)
        builder = builder.subject_name(subject.name)

        # Add extensions
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)

        # Get authorityKeyIdentifier from subjectKeyIdentifier from signing CA
        ca_subject_key_id = ca.x509.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        auth_key_id = x509.AuthorityKeyIdentifier(
            key_identifier=ca_subject_key_id.value.digest, authority_cert_issuer=None,
            authority_cert_serial_number=None)
        builder = builder.add_extension(auth_key_id, critical=False)

        for critical, ext in self.get_common_extensions(ca.issuer_url, ca.crl_url, ca.ocsp_url):
            builder = builder.add_extension(ext, critical=critical)

        if subjectAltName:
            builder = builder.add_extension(x509.SubjectAlternativeName(subjectAltName), critical=False)

        if key_usage:
            builder = builder.add_extension(**key_usage.for_builder())

        if extended_key_usage:
            builder = builder.add_extension(**extended_key_usage.for_builder())

        if tls_feature:
            builder = builder.add_extension(**tls_feature.for_builder())

        if ca.issuer_alt_name:
            builder = builder.add_extension(x509.IssuerAlternativeName(
                [parse_general_name(ca.issuer_alt_name)]), critical=False)

        return builder.sign(private_key=ca.key(password), algorithm=algorithm, backend=default_backend()), req

    def init(self, ca, csr, **kwargs):
        """Create a signed certificate from a CSR and store it to the database.

        All parameters are passed on to :py:func:`Certificate.objects.sign_cert()
        <django_ca.managers.CertificateManager.sign_cert>`.
        """

        pre_issue_cert.send(sender=self.model, ca=ca, csr=csr, **kwargs)

        c = self.model(ca=ca)
        c.x509, csr = self.sign_cert(ca, csr, **kwargs)
        c.csr = csr.public_bytes(Encoding.PEM).decode('utf-8')
        c.save()

        post_issue_cert.send(sender=self.model, cert=c)
        return c
