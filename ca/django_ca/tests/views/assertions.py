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

"""Assertions related to views."""

from datetime import datetime, timedelta, timezone
from typing import Optional, Union, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPublicKeyTypes
from cryptography.x509 import ocsp
from cryptography.x509.oid import OCSPExtensionOID, SignatureAlgorithmOID

from django_ca.models import Certificate, CertificateAuthority
from django_ca.tests.base.typehints import HttpResponse


def assert_ocsp_signature(public_key: CertificateIssuerPublicKeyTypes, response: ocsp.OCSPResponse) -> None:
    """Validate `response` with the given `public_key`."""
    tbs_response = response.tbs_response_bytes
    hash_algorithm = response.signature_hash_algorithm

    if isinstance(public_key, rsa.RSAPublicKey):
        hash_algorithm = cast(hashes.HashAlgorithm, hash_algorithm)  # to make mypy happy
        assert public_key.verify(response.signature, tbs_response, padding.PKCS1v15(), hash_algorithm) is None

    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        hash_algorithm = cast(hashes.HashAlgorithm, hash_algorithm)  # to make mypy happy
        assert public_key.verify(response.signature, tbs_response, ec.ECDSA(hash_algorithm)) is None
    elif isinstance(public_key, dsa.DSAPublicKey):
        hash_algorithm = cast(hashes.HashAlgorithm, hash_algorithm)  # to make mypy happy
        public_key.verify(response.signature, tbs_response, hash_algorithm)
    elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        public_key.verify(response.signature, tbs_response)
    else:  # pragma: no cover
        # All valid types should be implemented, but if you see this happen, go here:
        #   https://cryptography.io/en/latest/hazmat/primitives/asymmetric/
        raise ValueError(f"Unsupported public key type: {public_key}")


def assert_certificate_status(
    certificate: Union[Certificate, CertificateAuthority],
    response: Union[ocsp.OCSPResponse, ocsp.OCSPSingleResponse],
) -> None:
    """Check information related to the certificate status."""
    if certificate.revoked is False:
        assert response.certificate_status == ocsp.OCSPCertStatus.GOOD
        assert response.revocation_time_utc is None
        assert response.revocation_reason is None
    else:
        assert response.certificate_status == ocsp.OCSPCertStatus.REVOKED
        assert response.revocation_reason == certificate.get_revocation_reason()
        assert response.revocation_time_utc == certificate.get_revocation_time()


def assert_ocsp_single_response(
    certificate: Union[Certificate, CertificateAuthority],
    response: ocsp.OCSPSingleResponse,
    hash_algorithm: type[hashes.HashAlgorithm] = hashes.SHA256,
) -> None:
    """Assert properties of OCSP Single responses.

    Note that `hash_algorithm` cannot be ``None``, as it must match the algorithm of the OCSP request.
    """
    assert_certificate_status(certificate, response)
    assert response.serial_number == certificate.pub.loaded.serial_number
    assert isinstance(response.hash_algorithm, hash_algorithm)


def assert_ocsp_response(
    http_response: "HttpResponse",
    requested_certificate: Union[Certificate, CertificateAuthority],
    responder_certificate: Certificate,
    response_status: ocsp.OCSPResponseStatus = ocsp.OCSPResponseStatus.SUCCESSFUL,
    nonce: Optional[bytes] = None,
    expires: int = 86400,
    signature_hash_algorithm: Optional[type[hashes.HashAlgorithm]] = hashes.SHA256,
    signature_algorithm_oid: x509.ObjectIdentifier = SignatureAlgorithmOID.RSA_WITH_SHA256,
    single_response_hash_algorithm: type[hashes.HashAlgorithm] = hashes.SHA256,
) -> None:
    """Assert an OCSP request."""
    assert http_response["Content-Type"] == "application/ocsp-response"

    response = ocsp.load_der_ocsp_response(http_response.content)

    assert response.response_status == response_status
    if signature_hash_algorithm is None:
        assert response.signature_hash_algorithm is None
    else:
        assert isinstance(response.signature_hash_algorithm, signature_hash_algorithm)
    assert response.signature_algorithm_oid == signature_algorithm_oid
    assert response.certificates == [responder_certificate.pub.loaded]  # responder certificate!
    assert response.responder_name is None
    assert isinstance(response.responder_key_hash, bytes)  # TODO: Validate responder id
    # TODO: validate issuer_key_hash, issuer_name_hash

    # Check TIMESTAMPS
    now = datetime.now(tz=timezone.utc)
    assert response.this_update_utc == now
    assert response.next_update_utc == now + timedelta(seconds=expires)

    # Check nonce if passed
    if nonce is None:
        assert len(response.extensions) == 0
    else:
        nonce_extension = response.extensions.get_extension_for_oid(OCSPExtensionOID.NONCE)
        assert nonce_extension.critical is False
        assert nonce_extension.value.nonce == nonce  # type: ignore[attr-defined]

    assert response.serial_number == requested_certificate.pub.loaded.serial_number

    # Check the certificate status
    assert_certificate_status(requested_certificate, response)

    # Assert single response
    single_responses = list(response.responses)  # otherwise it has no len()/index
    assert len(single_responses) == 1
    assert_ocsp_single_response(requested_certificate, single_responses[0], single_response_hash_algorithm)

    public_key = cast(CertificateIssuerPublicKeyTypes, responder_certificate.pub.loaded.public_key())
    assert_ocsp_signature(public_key, response)
