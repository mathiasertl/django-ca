# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca. If not, see
# <http://www.gnu.org/licenses/>.

"""OCSP key backend storing private keys in the database."""

import typing

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat
from cryptography.x509.ocsp import OCSPResponse, OCSPResponseBuilder

from django_ca.key_backends import OCSPKeyBackend
from django_ca.models import CertificateAuthority
from django_ca.typehints import ParsableKeyType, SignatureHashAlgorithm
from django_ca.utils import generate_private_key


class DBOCSPBackend(OCSPKeyBackend):
    """OCSP key backend storing files in the database."""

    def create_private_key(
        self,
        ca: "CertificateAuthority",
        key_type: ParsableKeyType,
        key_size: int | None,
        elliptic_curve: ec.EllipticCurve | None,
    ) -> x509.CertificateSigningRequest:
        # Generate the private key.
        private_key = generate_private_key(key_size, key_type, elliptic_curve)

        # Serialize and store the key
        encryption = serialization.NoEncryption()
        pem = private_key.private_bytes(
            encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=encryption
        )

        ca.ocsp_key_backend_options["private_key"]["pem"] = pem.decode()

        # Generate the CSR to return to the caller.
        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([]))
        csr_algorithm = self.get_csr_algorithm(key_type)
        return csr_builder.sign(private_key, csr_algorithm)

    def sign_ocsp_response(
        self,
        ca: "CertificateAuthority",
        builder: OCSPResponseBuilder,
        signature_hash_algorithm: SignatureHashAlgorithm | None,
    ) -> OCSPResponse:
        pem = ca.ocsp_key_backend_options["private_key"]["pem"].encode()
        key = typing.cast(CertificateIssuerPrivateKeyTypes, serialization.load_pem_private_key(pem, None))
        return builder.sign(key, signature_hash_algorithm)
