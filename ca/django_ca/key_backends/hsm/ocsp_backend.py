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

"""OCSP key backend using HSMs."""

from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Optional

from pkcs11 import Session

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.ocsp import OCSPResponse, OCSPResponseBuilder

from django_ca.constants import ELLIPTIC_CURVE_NAMES
from django_ca.key_backends import OCSPKeyBackend
from django_ca.key_backends.hsm.keys import (
    PKCS11Ed448PrivateKey,
    PKCS11Ed25519PrivateKey,
    PKCS11EllipticCurvePrivateKey,
    PKCS11PrivateKeyTypes,
    PKCS11RSAPrivateKey,
)
from django_ca.key_backends.hsm.mixins import HSMKeyBackendMixin
from django_ca.typehints import AllowedHashTypes, ParsableKeyType
from django_ca.utils import int_to_hex

if TYPE_CHECKING:
    from django_ca.models import CertificateAuthority


class HSMOCSPBackend(HSMKeyBackendMixin, OCSPKeyBackend):
    """OCSP key backend storing files on the local file system."""

    # Backend options
    storage_alias: str
    path: str
    encrypt_private_key: bool

    @contextmanager
    def session(self, rw: bool = False) -> Iterator[Session]:  # type: ignore[override]
        with super().session(so_pin=self.so_pin, user_pin=self.user_pin, rw=rw) as session:
            yield session

    def create_private_key(
        self,
        ca: "CertificateAuthority",
        key_type: ParsableKeyType,
        key_size: Optional[int],
        elliptic_curve: Optional[ec.EllipticCurve],
    ) -> x509.CertificateSigningRequest:
        key_id = int_to_hex(x509.random_serial_number())
        key_label = f"ocsp_{key_id}"

        elliptic_curve_name = None
        if elliptic_curve is not None:
            elliptic_curve_name = ELLIPTIC_CURVE_NAMES[type(elliptic_curve)]

        with self.session(rw=True) as session:
            # Generate the private key.
            private_key = self._create_private_key(
                session,
                key_id,
                key_label,
                key_type,
                key_size=key_size,
                elliptic_curve=elliptic_curve_name,
            )

            # Generate the CSR to return to the caller.
            csr_builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([]))
            csr_algorithm = self.get_csr_algorithm(key_type)
            csr = csr_builder.sign(private_key, csr_algorithm)

        ca.ocsp_key_backend_options["private_key"]["key_id"] = key_id
        ca.ocsp_key_backend_options["private_key"]["key_label"] = key_label
        ca.ocsp_key_backend_options["private_key"]["key_type"] = key_type
        return csr

    def sign_ocsp_response(
        self,
        ca: "CertificateAuthority",
        builder: OCSPResponseBuilder,
        signature_hash_algorithm: Optional[AllowedHashTypes],
    ) -> OCSPResponse:
        key_id = ca.ocsp_key_backend_options["private_key"]["key_id"]
        key_label = ca.ocsp_key_backend_options["private_key"]["key_label"]
        key_type = ca.ocsp_key_backend_options["private_key"]["key_type"]

        with self.session() as session:
            if key_type == "RSA":
                private_key: PKCS11PrivateKeyTypes = PKCS11RSAPrivateKey(session, key_id, key_label)
            elif key_type == "Ed448":
                private_key = PKCS11Ed448PrivateKey(session, key_id, key_label)
            elif key_type == "Ed25519":
                private_key = PKCS11Ed25519PrivateKey(session, key_id, key_label)
            elif key_type == "EC":
                private_key = PKCS11EllipticCurvePrivateKey(session, key_id, key_label)
            else:  # pragma: no cover
                raise ValueError(f"{key_type}: Unsupported key type.")

            return builder.sign(private_key, signature_hash_algorithm)
