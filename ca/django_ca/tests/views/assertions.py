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

from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import ocsp

from django_ca.models import Certificate, CertificateAuthority
from django_ca.tests.base.assertions import assert_ocsp_response
from django_ca.tests.base.typehints import HttpResponse


def assert_ocsp_response_via_http(
    http_response: "HttpResponse",
    requested_certificate: Certificate | CertificateAuthority,
    response_status: ocsp.OCSPResponseStatus = ocsp.OCSPResponseStatus.SUCCESSFUL,
    certificate_status: ocsp.OCSPCertStatus = ocsp.OCSPCertStatus.GOOD,
    nonce: bytes | None = None,
    expires: timedelta = timedelta(seconds=86400),
    signature_hash_algorithm: type[hashes.HashAlgorithm] | None = hashes.SHA256,
    single_response_hash_algorithm: type[hashes.HashAlgorithm] = hashes.SHA256,
) -> None:
    """Assert an OCSP request."""
    assert http_response["Content-Type"] == "application/ocsp-response"

    if isinstance(requested_certificate, Certificate):
        signer = requested_certificate.ca
    else:
        assert requested_certificate.parent is not None, "Cannot generate an OCSP request for a root CA."
        signer = requested_certificate.parent

    responder_pem = signer.ocsp_key_backend_options["certificate"]["pem"].encode()
    responder_certificate = x509.load_pem_x509_certificate(responder_pem)

    assert_ocsp_response(
        http_response.content,
        requested_certificate,
        responder_certificate=responder_certificate,
        response_status=response_status,
        certificate_status=certificate_status,
        nonce=nonce,
        expires=expires,
        signature_hash_algorithm=signature_hash_algorithm,
        single_response_hash_algorithm=single_response_hash_algorithm,
    )
