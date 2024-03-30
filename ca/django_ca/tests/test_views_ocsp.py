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

"""Test OCSP related views."""

import base64
import typing
from datetime import datetime, timedelta
from http import HTTPStatus
from typing import Optional, Tuple, Type, Union
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificateIssuerPublicKeyTypes,
)
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, load_der_private_key
from cryptography.x509 import ocsp
from cryptography.x509.oid import OCSPExtensionOID, SignatureAlgorithmOID

from django.core.files.storage import storages
from django.test import TestCase, override_settings
from django.urls import path, re_path, reverse

from freezegun import freeze_time

from django_ca.constants import ReasonFlags
from django_ca.key_backends.storages import UsePrivateKeyOptions
from django_ca.modelfields import LazyCertificate
from django_ca.models import Certificate, CertificateAuthority
from django_ca.tests.base.constants import CERT_DATA, FIXTURES_DATA, FIXTURES_DIR, TIMESTAMPS
from django_ca.tests.base.mixins import TestCaseMixin
from django_ca.tests.base.typehints import HttpResponse
from django_ca.tests.base.utils import override_tmpcadir
from django_ca.utils import get_storage, hex_to_bytes
from django_ca.views import OCSPView


# openssl ocsp -issuer django_ca/tests/fixtures/root.pem -serial <serial> \
#         -reqout django_ca/tests/fixtures/ocsp/unknown-serial -resp_text
#
# WHERE serial is an int: (int('0x<hex>'.replace(':', '').lower(), 0)
def _load_req(req: str) -> bytes:
    with open(FIXTURES_DIR / "ocsp" / req, "rb") as stream:
        return stream.read()


ocsp_profile = CERT_DATA["profile-ocsp"]
ocsp_key_path = ocsp_profile["key_path"]
ocsp_pem_path = ocsp_profile["pub_path"]
ocsp_pem = ocsp_profile["pub"]["pem"]
req1 = _load_req(FIXTURES_DATA["ocsp"]["nonce"]["filename"])
req1_nonce = hex_to_bytes(FIXTURES_DATA["ocsp"]["nonce"]["nonce"])
req_no_nonce = _load_req(FIXTURES_DATA["ocsp"]["no-nonce"]["filename"])
unknown_req = _load_req("unknown-serial")
multiple_req = _load_req("multiple-serial")

urlpatterns = [
    path(
        "ocsp/",
        OCSPView.as_view(
            ca=CERT_DATA["child"]["serial"],
            responder_key=ocsp_profile["key_filename"],
            responder_cert=ocsp_profile["pub_filename"],
            expires=1200,
        ),
        name="post",
    ),
    path(
        "ocsp/serial/",
        OCSPView.as_view(
            ca=CERT_DATA["child"]["serial"],
            responder_key=ocsp_profile["key_filename"],
            responder_cert=CERT_DATA["profile-ocsp"]["serial"],
            expires=1300,
        ),
        name="post-serial",
    ),
    path(
        "ocsp/full-pem/",
        OCSPView.as_view(
            ca=CERT_DATA["child"]["serial"],
            responder_key=ocsp_profile["key_filename"],
            responder_cert=ocsp_pem,
            expires=1400,
        ),
        name="post-full-pem",
    ),
    path(
        "ocsp/loaded-cryptography/",
        OCSPView.as_view(
            ca=CERT_DATA["child"]["serial"],
            responder_key=ocsp_profile["key_filename"],
            responder_cert=CERT_DATA["profile-ocsp"]["pub"]["parsed"],
            expires=1500,
        ),
        name="post-loaded-cryptography",
    ),
    re_path(
        r"^ocsp/cert/(?P<data>[a-zA-Z0-9=+/]+)$",
        OCSPView.as_view(
            ca=CERT_DATA["child"]["serial"],
            responder_key=ocsp_profile["key_filename"],
            responder_cert=ocsp_profile["pub_filename"],
        ),
        name="get",
    ),
    re_path(
        r"^ocsp/ca/(?P<data>[a-zA-Z0-9=+/]+)$",
        OCSPView.as_view(
            ca=CERT_DATA["root"]["serial"],
            responder_key=ocsp_profile["key_filename"],
            responder_cert=ocsp_profile["pub_filename"],
            ca_ocsp=True,
        ),
        name="get-ca",
    ),
    re_path(
        r"^ocsp-unknown/(?P<data>[a-zA-Z0-9=+/]+)$",
        OCSPView.as_view(
            ca="unknown",
            responder_key=ocsp_profile["key_filename"],
            responder_cert=ocsp_profile["pub_filename"],
        ),
        name="unknown",
    ),
    re_path(
        r"^ocsp/false-key/(?P<data>[a-zA-Z0-9=+/]+)$",
        OCSPView.as_view(
            ca=CERT_DATA["child"]["serial"],
            responder_key="foobar",
            responder_cert=ocsp_profile["pub_filename"],
            expires=1200,
        ),
        name="false-key",
    ),
    # set invalid responder_certs
    re_path(
        r"^ocsp/false-pem-serial/(?P<data>[a-zA-Z0-9=+/]+)$",
        OCSPView.as_view(
            ca=CERT_DATA["child"]["serial"],
            responder_key=ocsp_profile["key_filename"],
            responder_cert="AA:BB:CC",
        ),
        name="false-pem-serial",
    ),
    re_path(
        r"^ocsp/false-pem-full/(?P<data>[a-zA-Z0-9=+/]+)$",
        OCSPView.as_view(
            ca=CERT_DATA["child"]["serial"],
            responder_key=ocsp_profile["key_filename"],
            responder_cert="-----BEGIN CERTIFICATE-----\nvery-mean!",
        ),
        name="false-pem-full",
    ),
]


class OCSPViewTestMixin(TestCaseMixin):
    """Mixin for OCSP view tests."""

    def assertOCSPSignature(  # pylint: disable=invalid-name
        self,
        public_key: CertificateIssuerPublicKeyTypes,
        response: ocsp.OCSPResponse,
    ) -> None:
        """Validate `response` with the given `public_key`."""
        tbs_response = response.tbs_response_bytes
        hash_algorithm = response.signature_hash_algorithm

        if isinstance(public_key, rsa.RSAPublicKey):
            hash_algorithm = typing.cast(hashes.HashAlgorithm, hash_algorithm)  # to make mypy happy
            self.assertIsNone(
                public_key.verify(response.signature, tbs_response, padding.PKCS1v15(), hash_algorithm)
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            hash_algorithm = typing.cast(hashes.HashAlgorithm, hash_algorithm)  # to make mypy happy
            self.assertIsNone(public_key.verify(response.signature, tbs_response, ec.ECDSA(hash_algorithm)))
        elif isinstance(public_key, dsa.DSAPublicKey):
            hash_algorithm = typing.cast(hashes.HashAlgorithm, hash_algorithm)  # to make mypy happy
            public_key.verify(response.signature, tbs_response, hash_algorithm)
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(response.signature, tbs_response)
        else:
            # All valid types should be implemented, but if you see this happen, go here:
            #   https://cryptography.io/en/latest/hazmat/primitives/asymmetric/
            raise ValueError(f"Unsupported public key type: {public_key}")

    def assertCertificateStatus(  # pylint: disable=invalid-name
        self,
        certificate: Union[Certificate, CertificateAuthority],
        response: Union[ocsp.OCSPResponse, ocsp.OCSPSingleResponse],
    ) -> None:
        """Check information related to the certificate status."""
        if certificate.revoked is False:
            self.assertEqual(response.certificate_status, ocsp.OCSPCertStatus.GOOD)
            self.assertIsNone(response.revocation_time)
            self.assertIsNone(response.revocation_reason)
        else:
            self.assertEqual(response.certificate_status, ocsp.OCSPCertStatus.REVOKED)
            self.assertEqual(response.revocation_reason, certificate.get_revocation_reason())
            self.assertEqual(response.revocation_time, certificate.get_revocation_time())

    def assertOCSPSingleResponse(  # pylint: disable=invalid-name
        self,
        certificate: Union[Certificate, CertificateAuthority],
        response: ocsp.OCSPSingleResponse,
        hash_algorithm: Type[hashes.HashAlgorithm] = hashes.SHA256,
    ) -> None:
        """Assert properties of OCSP Single responses.

        Note that `hash_algorithm` cannot be ``None``, as it must match the algorithm of the OCSP request.
        """
        self.assertCertificateStatus(certificate, response)
        self.assertEqual(response.serial_number, certificate.pub.loaded.serial_number)
        self.assertIsInstance(response.hash_algorithm, hash_algorithm)

    def assertOCSPResponse(  # pylint: disable=invalid-name
        self,
        http_response: "HttpResponse",
        requested_certificate: Union[Certificate, CertificateAuthority],
        response_status: ocsp.OCSPResponseStatus = ocsp.OCSPResponseStatus.SUCCESSFUL,
        nonce: Optional[bytes] = None,
        expires: int = 86400,
        responder_certificate: Optional[Certificate] = None,
        signature_hash_algorithm: Optional[Type[hashes.HashAlgorithm]] = hashes.SHA256,
        signature_algorithm_oid: x509.ObjectIdentifier = SignatureAlgorithmOID.RSA_WITH_SHA256,
        single_response_hash_algorithm: Type[hashes.HashAlgorithm] = hashes.SHA256,
    ) -> None:
        """Assert an OCSP request."""
        if responder_certificate is None:
            responder_certificate = self.certs["profile-ocsp"]

        self.assertEqual(http_response["Content-Type"], "application/ocsp-response")

        response = ocsp.load_der_ocsp_response(http_response.content)

        self.assertEqual(response.response_status, response_status)
        if signature_hash_algorithm is None:
            self.assertIsNone(response.signature_hash_algorithm)
        else:
            self.assertIsInstance(response.signature_hash_algorithm, signature_hash_algorithm)
        self.assertEqual(response.signature_algorithm_oid, signature_algorithm_oid)
        self.assertEqual(response.certificates, [responder_certificate.pub.loaded])  # responder certificate!
        self.assertIsNone(response.responder_name)
        self.assertIsInstance(response.responder_key_hash, bytes)  # TODO: Validate responder id
        # TODO: validate issuer_key_hash, issuer_name_hash

        # Check TIMESTAMPS
        # self.assertEqual(response.produced_at, datetime.now())
        self.assertEqual(response.this_update, datetime.now())
        self.assertEqual(response.next_update, datetime.now() + timedelta(seconds=expires))

        # Check nonce if passed
        if nonce is None:
            self.assertEqual(len(response.extensions), 0)
        else:
            nonce_extension = response.extensions.get_extension_for_oid(OCSPExtensionOID.NONCE)
            self.assertIs(nonce_extension.critical, False)
            self.assertEqual(nonce_extension.value.nonce, nonce)  # type: ignore[attr-defined]

        self.assertEqual(response.serial_number, requested_certificate.pub.loaded.serial_number)

        # Check the certificate status
        self.assertCertificateStatus(requested_certificate, response)

        # Assert single response
        single_responses = list(response.responses)  # otherwise it has no len()/index
        self.assertEqual(len(single_responses), 1)
        self.assertOCSPSingleResponse(
            requested_certificate, single_responses[0], single_response_hash_algorithm
        )

        public_key = typing.cast(
            CertificateIssuerPublicKeyTypes, responder_certificate.pub.loaded.public_key()
        )
        self.assertOCSPSignature(public_key, response)

    def generate_ocsp_key(
        self, ca: CertificateAuthority
    ) -> Tuple[CertificateIssuerPrivateKeyTypes, Certificate]:
        """Generate an OCSP key for the given CA and return private kay and public key model instance."""
        key_backend_options = UsePrivateKeyOptions(password=CERT_DATA[ca.name].get("password"))
        priv_path, _cert_path, ocsp_cert = ca.generate_ocsp_key(key_backend_options)  # type: ignore[misc]
        with storages["django-ca"].open(priv_path, "rb") as stream:
            private_key = typing.cast(
                CertificateIssuerPrivateKeyTypes, load_der_private_key(stream.read(), None)
            )
        return private_key, ocsp_cert

    def ocsp_get(
        self,
        certificate: Certificate,
        nonce: Optional[bytes] = None,
        hash_algorithm: Type[hashes.HashAlgorithm] = hashes.SHA256,
    ) -> "HttpResponse":
        """Make an OCSP get request."""
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(certificate.pub.loaded, certificate.ca.pub.loaded, hash_algorithm())

        if nonce is not None:  # Add Nonce if requested
            builder = builder.add_extension(x509.OCSPNonce(nonce), False)

        request = builder.build()

        url = reverse(
            "django_ca:ocsp-cert-get",
            kwargs={
                "serial": certificate.ca.serial,
                "data": base64.b64encode(request.public_bytes(Encoding.DER)).decode("utf-8"),
            },
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, HTTPStatus.OK)
        return response


class OCSPManualViewTestCaseMixin(OCSPViewTestMixin):
    """Mixin defining test cases for OCSPView.

    Why is this a separate mixin: https://github.com/spulec/freezegun/issues/485
    """

    load_cas = "__usable__"
    load_certs = "__usable__"

    @override_tmpcadir()
    def test_get(self) -> None:
        """Basic GET test."""
        data = base64.b64encode(req1).decode("utf-8")
        response = self.client.get(reverse("get", kwargs={"data": data}))
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertOCSPResponse(
            response,
            requested_certificate=self.cert,
            nonce=req1_nonce,
            expires=600,
            single_response_hash_algorithm=hashes.SHA1,
        )

    def test_bad_query(self) -> None:
        """Test sending a bad query."""
        response = self.client.get(reverse("get", kwargs={"data": "XXX"}))
        self.assertEqual(response.status_code, HTTPStatus.OK)
        ocsp_response = ocsp.load_der_ocsp_response(response.content)
        self.assertEqual(ocsp_response.response_status, ocsp.OCSPResponseStatus.MALFORMED_REQUEST)

    def test_raises_exception(self) -> None:
        """Generic test if the handling function throws any uncaught exception."""
        exception_str = f"{__name__}.{self.__class__.__name__}.test_raises_exception"
        ex = Exception(exception_str)

        data = base64.b64encode(req1).decode("utf-8")
        view_path = "django_ca.views.OCSPView.process_ocsp_request"
        with mock.patch(view_path, side_effect=ex), self.assertLogs() as logcm:
            response = self.client.get(reverse("get", kwargs={"data": data}))

        self.assertEqual(response.status_code, HTTPStatus.OK)
        ocsp_response = ocsp.load_der_ocsp_response(response.content)
        self.assertEqual(ocsp_response.response_status, ocsp.OCSPResponseStatus.INTERNAL_ERROR)
        self.assertEqual(len(logcm.output), 1)
        self.assertIn(exception_str, logcm.output[0])

        # also do a post request
        with mock.patch(view_path, side_effect=ex), self.assertLogs() as logcm:
            response = self.client.post(reverse("post"), req1, content_type="application/ocsp-request")
        self.assertEqual(response.status_code, HTTPStatus.OK)
        ocsp_response = ocsp.load_der_ocsp_response(response.content)
        self.assertEqual(ocsp_response.response_status, ocsp.OCSPResponseStatus.INTERNAL_ERROR)
        self.assertEqual(len(logcm.output), 1)
        self.assertIn(exception_str, logcm.output[0])

    @override_tmpcadir()
    def test_post(self) -> None:
        """Test the post request."""
        response = self.client.post(reverse("post"), req1, content_type="application/ocsp-request")
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertOCSPResponse(
            response,
            requested_certificate=self.cert,
            nonce=req1_nonce,
            expires=1200,
            single_response_hash_algorithm=hashes.SHA1,
        )

        response = self.client.post(
            reverse("post-serial"),
            req1,
            content_type="application/ocsp-request",
            single_response_hash_algorithm=hashes.SHA1,
        )
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertOCSPResponse(
            response,
            requested_certificate=self.cert,
            nonce=req1_nonce,
            expires=1300,
            single_response_hash_algorithm=hashes.SHA1,
        )

        response = self.client.post(reverse("post-full-pem"), req1, content_type="application/ocsp-request")
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertOCSPResponse(
            response,
            requested_certificate=self.cert,
            nonce=req1_nonce,
            expires=1400,
            single_response_hash_algorithm=hashes.SHA1,
        )

    @override_tmpcadir()
    def test_loaded_cryptography_cert(self) -> None:
        """Test view with loaded cryptography cert."""
        response = self.client.post(
            reverse("post-loaded-cryptography"), req1, content_type="application/ocsp-request"
        )
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertOCSPResponse(
            response,
            requested_certificate=self.cert,
            nonce=req1_nonce,
            expires=1500,
            single_response_hash_algorithm=hashes.SHA1,
        )

    @override_tmpcadir()
    def test_revoked(self) -> None:
        """Test fetching for revoked certificate."""
        self.cert.revoke()

        response = self.client.post(reverse("post"), req1, content_type="application/ocsp-request")
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertOCSPResponse(
            response,
            requested_certificate=self.cert,
            nonce=req1_nonce,
            expires=1200,
            single_response_hash_algorithm=hashes.SHA1,
        )

        self.cert.revoke(ReasonFlags.affiliation_changed)
        response = self.client.post(reverse("post"), req1, content_type="application/ocsp-request")
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertOCSPResponse(
            response,
            requested_certificate=self.cert,
            nonce=req1_nonce,
            expires=1200,
            single_response_hash_algorithm=hashes.SHA1,
        )

    @override_tmpcadir()
    def test_ca_ocsp(self) -> None:
        """Make a CA OCSP request."""
        # req1 has serial for self.cert hard-coded, so we update the child CA to contain data for self.cert
        ca = self.cas["child"]
        ca.serial = self.cert.serial
        ca.pub = self.cert.pub
        ca.save()

        data = base64.b64encode(req1).decode("utf-8")
        response = self.client.get(reverse("get-ca", kwargs={"data": data}))
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertOCSPResponse(
            response,
            requested_certificate=ca,
            nonce=req1_nonce,
            expires=600,
            single_response_hash_algorithm=hashes.SHA1,
        )

    def test_bad_ca(self) -> None:
        """Fetch data for a CA that does not exist."""
        data = base64.b64encode(req1).decode("utf-8")
        with self.assertLogs() as logcm:
            response = self.client.get(reverse("unknown", kwargs={"data": data}))
        self.assertEqual(
            logcm.output,
            [
                "ERROR:django_ca.views:unknown: Certificate Authority could not be found.",
            ],
        )

        self.assertEqual(response.status_code, HTTPStatus.OK)
        ocsp_response = ocsp.load_der_ocsp_response(response.content)
        self.assertEqual(ocsp_response.response_status, ocsp.OCSPResponseStatus.INTERNAL_ERROR)

    def test_unknown(self) -> None:
        """Test fetching data for an unknown certificate."""
        data = base64.b64encode(unknown_req).decode("utf-8")
        with self.assertLogs() as logcm:
            response = self.client.get(reverse("get", kwargs={"data": data}))
        self.assertEqual(
            logcm.output,
            [
                "WARNING:django_ca.views:7B: OCSP request for unknown cert received.",
            ],
        )
        self.assertEqual(response.status_code, HTTPStatus.OK)
        ocsp_response = ocsp.load_der_ocsp_response(response.content)
        self.assertEqual(ocsp_response.response_status, ocsp.OCSPResponseStatus.INTERNAL_ERROR)

    @override_tmpcadir()
    def test_unknown_ca(self) -> None:
        """Try requesting an unknown CA in a CA OCSP view."""
        data = base64.b64encode(req1).decode("utf-8")
        with self.assertLogs() as logcm:
            response = self.client.get(reverse("get-ca", kwargs={"data": data}))
        serial = self.certs["child-cert"].serial
        self.assertEqual(
            logcm.output, [f"WARNING:django_ca.views:{serial}: OCSP request for unknown CA received."]
        )
        self.assertEqual(response.status_code, HTTPStatus.OK)
        ocsp_response = ocsp.load_der_ocsp_response(response.content)
        self.assertEqual(ocsp_response.response_status, ocsp.OCSPResponseStatus.INTERNAL_ERROR)

    @override_tmpcadir()
    def test_bad_private_key_type(self) -> None:
        """Test that we log an error when the private key is of an unsupported type."""
        data = base64.b64encode(req1).decode("utf-8")

        with (
            self.assertLogs() as logcm,
            self.patch(
                "cryptography.hazmat.primitives.serialization.load_der_private_key",
                spec_set=True,
                return_value="wrong",  # usually would be an unsupported key type
            ),
        ):
            response = self.client.get(reverse("get", kwargs={"data": data}))
        ocsp_response = ocsp.load_der_ocsp_response(response.content)
        self.assertEqual(ocsp_response.response_status, ocsp.OCSPResponseStatus.INTERNAL_ERROR)
        self.assertEqual(
            logcm.output,
            [
                "ERROR:django_ca.views:<class 'str'>: Unsupported private key type.",
                "ERROR:django_ca.views:Could not read responder key/cert.",
            ],
        )

    def test_bad_responder_cert(self) -> None:
        """Test the error when the private key cannot be read.

        NOTE: since we don't use ``override_tmpcadir()`` here, the path to the key simply doesn't exist.
        """
        data = base64.b64encode(req1).decode("utf-8")

        with self.assertLogs() as logcm:
            response = self.client.get(reverse("get", kwargs={"data": data}))
        self.assertEqual(response.status_code, HTTPStatus.OK)
        ocsp_response = ocsp.load_der_ocsp_response(response.content)
        self.assertEqual(ocsp_response.response_status, ocsp.OCSPResponseStatus.INTERNAL_ERROR)
        self.assertEqual(logcm.output, ["ERROR:django_ca.views:Could not read responder key/cert."])

    def test_bad_request(self) -> None:
        """Try making a bad request."""
        data = base64.b64encode(b"foobar").decode("utf-8")
        with self.assertLogs() as logcm:
            response = self.client.get(reverse("get", kwargs={"data": data}))
        self.assertEqual(response.status_code, HTTPStatus.OK)
        ocsp_response = ocsp.load_der_ocsp_response(response.content)
        self.assertEqual(ocsp_response.response_status, ocsp.OCSPResponseStatus.MALFORMED_REQUEST)
        self.assertEqual(len(logcm.output), 1)
        self.assertIn("ValueError: error parsing asn1 value", logcm.output[0], logcm.output[0])

    def test_multiple(self) -> None:
        """Try making multiple OCSP requests (not currently supported)."""
        data = base64.b64encode(multiple_req).decode("utf-8")
        with self.assertLogs() as logcm:
            response = self.client.get(reverse("get", kwargs={"data": data}))
        self.assertEqual(response.status_code, HTTPStatus.OK)
        ocsp_response = ocsp.load_der_ocsp_response(response.content)
        self.assertEqual(ocsp_response.response_status, ocsp.OCSPResponseStatus.MALFORMED_REQUEST)
        self.assertEqual(len(logcm.output), 1)
        self.assertIn("OCSP request contains more than one request", logcm.output[0])

    @override_tmpcadir()
    def test_bad_ca_cert(self) -> None:
        """Try naming an invalid CA."""
        # NOTE: set LazyCertificate because this way we can avoid all value checking while saving.
        self.ca.pub = LazyCertificate(b"foobar")
        self.ca.save()

        data = base64.b64encode(req1).decode("utf-8")
        with self.assertLogs() as logcm:
            response = self.client.get(reverse("get", kwargs={"data": data}))
        self.assertEqual(response.status_code, HTTPStatus.OK)
        ocsp_response = ocsp.load_der_ocsp_response(response.content)
        self.assertEqual(ocsp_response.response_status, ocsp.OCSPResponseStatus.INTERNAL_ERROR)
        self.assertEqual(len(logcm.output), 1)
        self.assertIn("ValueError: ", logcm.output[0])

    @override_tmpcadir()
    def test_bad_responder_key(self) -> None:
        """Try configuring a bad responder key."""
        data = base64.b64encode(req1).decode("utf-8")

        with self.assertLogs() as logcm:
            response = self.client.get(reverse("false-key", kwargs={"data": data}))
        self.assertEqual(response.status_code, HTTPStatus.OK)
        ocsp_response = ocsp.load_der_ocsp_response(response.content)
        self.assertEqual(ocsp_response.response_status, ocsp.OCSPResponseStatus.INTERNAL_ERROR)
        self.assertEqual(logcm.output, ["ERROR:django_ca.views:Could not read responder key/cert."])

    @override_tmpcadir()
    def test_bad_responder_pem(self) -> None:
        """Try configuring a bad responder cert."""
        data = base64.b64encode(req1).decode("utf-8")
        msg = "ERROR:django_ca.views:Could not read responder key/cert."

        with self.assertLogs() as logcm:
            response = self.client.get(reverse("false-pem-serial", kwargs={"data": data}))
        self.assertEqual(logcm.output, [msg])
        self.assertEqual(response.status_code, HTTPStatus.OK)
        ocsp_response = ocsp.load_der_ocsp_response(response.content)
        self.assertEqual(ocsp_response.response_status, ocsp.OCSPResponseStatus.INTERNAL_ERROR)
        with self.assertLogs() as logcm:
            response = self.client.get(reverse("false-pem-full", kwargs={"data": data}))
        self.assertEqual(logcm.output, [msg])
        self.assertEqual(response.status_code, HTTPStatus.OK)
        ocsp_response = ocsp.load_der_ocsp_response(response.content)
        self.assertEqual(ocsp_response.response_status, ocsp.OCSPResponseStatus.INTERNAL_ERROR)


@override_settings(ROOT_URLCONF=__name__)
@freeze_time(TIMESTAMPS["everything_valid"])
class OCSPTestView(OCSPManualViewTestCaseMixin, TestCase):
    """Test manually configured OCSPView."""


@freeze_time(TIMESTAMPS["everything_valid"])
class GenericOCSPViewTestCase(OCSPViewTestMixin, TestCase):
    """Test generic OCSP view."""

    load_cas = ("root", "child")
    load_certs = ("child-cert",)

    @override_tmpcadir()
    def test_ocsp_get(self) -> None:
        """Test getting OCSP responses."""
        private_key, ocsp_cert = self.generate_ocsp_key(self.ca)

        response = self.ocsp_get(self.cert)

        self.assertOCSPResponse(response, requested_certificate=self.cert, responder_certificate=ocsp_cert)

    @override_tmpcadir()
    def test_ocsp_get_with_nonce(self) -> None:
        """Test OCSP responder via GET request while passing a nonce."""
        private_key, ocsp_cert = self.generate_ocsp_key(self.ca)

        response = self.ocsp_get(self.cert, nonce=b"foo")

        self.assertOCSPResponse(
            response, requested_certificate=self.cert, nonce=b"foo", responder_certificate=ocsp_cert
        )

    @override_tmpcadir()
    def test_ocsp_response_validity(self) -> None:
        """Test a custom OCSP response validity."""
        private_key, ocsp_cert = self.generate_ocsp_key(self.ca)

        # Reduce OCSP response validity before making request
        self.ca.ocsp_response_validity = 3600
        self.ca.save()

        response = self.ocsp_get(self.cert)

        # URL config sets expires to 3600
        self.assertOCSPResponse(
            response,
            requested_certificate=self.cert,
            expires=3600,
            responder_certificate=ocsp_cert,
        )

    @override_tmpcadir()
    def test_sha512_hash_algorithm(self) -> None:
        """Test the OCSP responder with an EC-based certificate authority."""
        private_key, ocsp_cert = self.generate_ocsp_key(self.ca)
        response = self.ocsp_get(self.cert, hash_algorithm=hashes.SHA512)

        self.assertOCSPResponse(
            response,
            requested_certificate=self.cert,
            responder_certificate=ocsp_cert,
            signature_algorithm_oid=SignatureAlgorithmOID.RSA_WITH_SHA256,
            single_response_hash_algorithm=hashes.SHA512,
        )

    @override_tmpcadir()
    def test_pem_responder_key(self) -> None:
        """Test the OCSP responder with PEM-encoded private key."""
        private_key, ocsp_cert = self.generate_ocsp_key(self.ca)

        # Overwrite key with PEM format
        storage = get_storage()
        private_path = storage.generate_filename(f"ocsp/{self.ca.serial.replace(':', '')}.key")
        pem_private_key = private_key.private_bytes(
            Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with storage.open(private_path, "wb") as stream:
            stream.write(pem_private_key)

        response = self.ocsp_get(self.cert, hash_algorithm=hashes.SHA512)

        self.assertOCSPResponse(
            response,
            requested_certificate=self.cert,
            responder_certificate=ocsp_cert,
            signature_algorithm_oid=SignatureAlgorithmOID.RSA_WITH_SHA256,
            single_response_hash_algorithm=hashes.SHA512,
        )

    @override_tmpcadir()
    def test_dsa_certificate_authority(self) -> None:
        """Test the OCSP responder with an EC-based certificate authority."""
        ca = self.load_ca("dsa")
        private_key, ocsp_cert = self.generate_ocsp_key(ca)

        cert = self.load_named_cert("dsa-cert")
        response = self.ocsp_get(cert)

        self.assertOCSPResponse(
            response,
            requested_certificate=cert,
            responder_certificate=ocsp_cert,
            signature_algorithm_oid=SignatureAlgorithmOID.DSA_WITH_SHA256,
        )

    @override_tmpcadir()
    def test_ec_certificate_authority(self) -> None:
        """Test the OCSP responder with an EC-based certificate authority."""
        ca = self.load_ca("ec")
        private_key, ocsp_cert = self.generate_ocsp_key(ca)

        cert = self.load_named_cert("ec-cert")
        response = self.ocsp_get(cert)

        self.assertOCSPResponse(
            response,
            requested_certificate=cert,
            responder_certificate=ocsp_cert,
            signature_algorithm_oid=SignatureAlgorithmOID.ECDSA_WITH_SHA256,
        )

    @override_tmpcadir()
    def test_ed448_certificate_authority(self) -> None:
        """Test the OCSP responder with an EC-based certificate authority."""
        ca = self.load_ca("ed448")
        private_key, ocsp_cert = self.generate_ocsp_key(ca)

        cert = self.load_named_cert("ed448-cert")
        response = self.ocsp_get(cert)

        self.assertOCSPResponse(
            response,
            requested_certificate=cert,
            responder_certificate=ocsp_cert,
            signature_hash_algorithm=None,
            signature_algorithm_oid=SignatureAlgorithmOID.ED448,
        )

    @override_tmpcadir()
    def test_invalid_responder_key(self) -> None:
        """Test the OCSP responder error when there is an invalid responder."""
        private_key, ocsp_cert = self.generate_ocsp_key(self.ca)

        # Overwrite key with PEM format
        storage = get_storage()
        private_path = storage.generate_filename(f"ocsp/{self.ca.serial.replace(':', '')}.key")
        with storage.open(private_path, "wb") as stream:
            stream.write(b"bogus")

        with self.assertLogs() as logcm:
            response = self.ocsp_get(self.cert, hash_algorithm=hashes.SHA512)
        self.assertEqual(logcm.output, ["ERROR:django_ca.views:Could not read responder key/cert."])
        self.assertEqual(response.status_code, HTTPStatus.OK)
        ocsp_response = ocsp.load_der_ocsp_response(response.content)
        self.assertEqual(ocsp_response.response_status, ocsp.OCSPResponseStatus.INTERNAL_ERROR)

    @override_tmpcadir()
    def test_ed25519_certificate_authority(self) -> None:
        """Test the OCSP responder with an EC-based certificate authority."""
        ca = self.load_ca("ed25519")
        private_key, ocsp_cert = self.generate_ocsp_key(ca)

        cert = self.load_named_cert("ed25519-cert")
        response = self.ocsp_get(cert)

        self.assertOCSPResponse(
            response,
            requested_certificate=cert,
            responder_certificate=ocsp_cert,
            signature_hash_algorithm=None,
            signature_algorithm_oid=SignatureAlgorithmOID.ED25519,
        )

    @override_tmpcadir()
    def test_cert_method_not_allowed(self) -> None:
        """Try HTTP methods that are not allowed."""
        url = reverse("django_ca:ocsp-cert-post", kwargs={"serial": "00AA"})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 405)

        url = reverse("django_ca:ocsp-cert-get", kwargs={"serial": "00AA", "data": "irrelevant"})
        response = self.client.post(url, req1, content_type="application/ocsp-request")
        self.assertEqual(response.status_code, 405)
