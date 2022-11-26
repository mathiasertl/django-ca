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

"""Views for the django-ca app.

.. seealso::

   * https://docs.djangoproject.com/en/dev/topics/class-based-views/
   * https://django-ca.readthedocs.io/en/latest/python/views.html
"""

import base64
import binascii
import logging
import os
import typing
from datetime import datetime, timedelta
from http import HTTPStatus

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ExtensionNotFound, OCSPNonce, load_pem_x509_certificate, ocsp

from django.core.cache import cache
from django.http import HttpRequest, HttpResponse, HttpResponseServerError
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import View
from django.views.generic.detail import SingleObjectMixin

from . import ca_settings
from .models import Certificate, CertificateAuthority
from .typehints import Literal, PrivateKeyTypes
from .utils import SERIAL_RE, get_crl_cache_key, int_to_hex, parse_encoding, read_file

log = logging.getLogger(__name__)

if typing.TYPE_CHECKING:
    from django.http.response import HttpResponseBase

    SingleObjectMixinBase = SingleObjectMixin[CertificateAuthority]
else:
    SingleObjectMixinBase = SingleObjectMixin


class CertificateRevocationListView(View, SingleObjectMixinBase):
    """Generic view that provides Certificate Revocation Lists (CRLs)."""

    slug_field = "serial"
    slug_url_kwarg = "serial"
    queryset = CertificateAuthority.objects.all().prefetch_related("certificate_set")

    password = None
    """Password used to load the private key of the certificate authority. If not set, the private key is
    assumed to be unencrypted."""

    # parameters for the CRL itself
    type = Encoding.DER
    """Encoding for CRL."""

    scope: typing.Optional[Literal["ca", "user", "attribute"]] = "user"
    """Set to ``"user"`` to limit CRL to certificates or ``"ca"`` to certificate authorities or ``None`` to
    include both."""

    expires = 600
    """CRL expires in this many seconds."""

    digest = hashes.SHA512()
    """Digest used for generating the CRL."""

    # header used in the request
    content_type = None
    """Value of the Content-Type header used in the response. For CRLs in PEM format, use ``text/plain``."""

    include_issuing_distribution_point: typing.Optional[bool] = None
    """Boolean flag to force inclusion/exclusion of IssuingDistributionPoint extension."""

    def get(self, request: HttpRequest, serial: str) -> HttpResponse:
        # pylint: disable=missing-function-docstring; standard Django view function
        encoding = parse_encoding(request.GET.get("encoding", self.type))
        cache_key = get_crl_cache_key(serial, algorithm=self.digest, encoding=encoding, scope=self.scope)

        crl = cache.get(cache_key)
        if crl is None:
            ca = self.get_object()

            # Catch this case early so that we can give a better error message
            if self.include_issuing_distribution_point is True and ca.parent is None and self.scope is None:
                raise ValueError(
                    "Cannot add IssuingDistributionPoint extension to CRLs with no scope for root CAs."
                )

            encoding = parse_encoding(self.type)
            crl = ca.get_crl(
                expires=self.expires,
                algorithm=self.digest,
                password=self.password,
                scope=self.scope,
                include_issuing_distribution_point=self.include_issuing_distribution_point,
            )
            crl = crl.public_bytes(encoding)
            cache.set(cache_key, crl, self.expires)

        content_type = self.content_type
        if content_type is None:
            if self.type == Encoding.DER:
                content_type = "application/pkix-crl"
            elif self.type == Encoding.PEM:
                content_type = "text/plain"
            else:  # pragma: no cover
                # DER/PEM are all known encoding types, so this shouldn't happen
                return HttpResponseServerError()

        return HttpResponse(crl, content_type=content_type)


@method_decorator(csrf_exempt, name="dispatch")
class OCSPView(View):
    """View to provide an OCSP responder."""

    ca: str = ""
    """The name or serial of your Certificate Authority."""

    responder_key: str = ""
    """Private key used for signing OCSP responses. A relative path used by :ref:`CA_FILE_STORAGE
    <settings-ca-file-storage>`."""

    responder_cert: typing.Union[x509.Certificate, str] = ""
    """Public key of the responder.

    This may either be:

    * A relative path used by :ref:`CA_FILE_STORAGE <settings-ca-file-storage>`
    * A serial of a certificate as stored in the database
    * The PEM of the certificate as string
    * A loaded :py:class:`~cg:cryptography.x509.Certificate`
    """

    expires = 600
    """Time in seconds that the responses remain valid. The default is 600 seconds or ten minutes."""

    ca_ocsp = False
    """If set to ``True``, validate child CAs instead."""

    def get(self, request: HttpRequest, data: str) -> HttpResponse:
        # pylint: disable=missing-function-docstring; standard Django view function
        try:
            decoded_data = base64.b64decode(data)
        except binascii.Error:
            return self.malformed_request()

        try:
            return self.process_ocsp_request(decoded_data)
        except Exception as e:  # pylint: disable=broad-except; we really need to catch everything here
            log.exception(e)
            return self.fail()

    def post(self, request: HttpRequest) -> HttpResponse:
        # pylint: disable=missing-function-docstring; standard Django view function
        try:
            return self.process_ocsp_request(request.body)
        except Exception as e:  # pylint: disable=broad-except; we really need to catch everything here
            log.exception(e)
            return self.fail()

    def fail(self, status: ocsp.OCSPResponseStatus = ocsp.OCSPResponseStatus.INTERNAL_ERROR) -> HttpResponse:
        """Generic method to return a failure response."""
        return self.http_response(
            ocsp.OCSPResponseBuilder.build_unsuccessful(status).public_bytes(Encoding.DER)
        )

    def get_responder_key(self) -> PrivateKeyTypes:
        """Get the private key used to sign OCSP responses."""
        key = self.get_responder_key_data()
        loaded_key = serialization.load_pem_private_key(key, None)

        # Check that the private key is of a supported type
        if not isinstance(loaded_key, (rsa.RSAPrivateKey, dsa.DSAPrivateKey, ec.EllipticCurvePrivateKey)):
            log.error("%s: Unsupported private key type.", type(loaded_key))
            raise ValueError(f"{type(loaded_key)}: Unsupported private key type.")

        return loaded_key

    def get_responder_key_data(self) -> bytes:
        """Read the file containing the private key used to sign OCSP responses."""
        return read_file(self.responder_key)

    def get_responder_cert(self) -> x509.Certificate:
        """Get the public key used to sign OCSP responses."""
        # User configured a loaded certificate
        if isinstance(self.responder_cert, x509.Certificate):
            return self.responder_cert

        if self.responder_cert.startswith("-----BEGIN CERTIFICATE-----\n"):
            responder_cert = self.responder_cert.encode("utf-8")
        elif SERIAL_RE.match(self.responder_cert):
            serial = self.responder_cert.replace(":", "")
            return Certificate.objects.get(serial=serial).pub.loaded
        else:
            if os.path.isabs(self.responder_cert):
                log.warning(
                    "%s: OCSP responder uses absolute path to certificate. Please see %s.",
                    self.responder_cert,
                    ca_settings.CA_FILE_STORAGE_URL,
                )
            responder_cert = read_file(self.responder_cert)

        return load_pem_x509_certificate(responder_cert)

    def get_ca(self) -> CertificateAuthority:
        """Get the certificate authority for the request."""
        return CertificateAuthority.objects.get_by_serial_or_cn(self.ca)

    def get_cert(
        self, ca: CertificateAuthority, serial: str
    ) -> typing.Union[Certificate, CertificateAuthority]:
        """Get the certificate that was requested in the OCSP request."""
        if self.ca_ocsp is True:
            return CertificateAuthority.objects.filter(parent=ca).get(serial=serial)

        return Certificate.objects.filter(ca=ca).get(serial=serial)

    def http_response(self, data: bytes, status: int = HTTPStatus.OK) -> HttpResponse:
        """Get a HTTP OCSP response with given status and data."""
        return HttpResponse(data, status=status, content_type="application/ocsp-response")

    def malformed_request(self) -> HttpResponse:
        """Get a response for a malformed request."""
        return self.fail(ocsp.OCSPResponseStatus.MALFORMED_REQUEST)

    def process_ocsp_request(self, data: bytes) -> HttpResponse:
        """Process OCSP request data."""

        try:
            ocsp_req = ocsp.load_der_ocsp_request(data)
        except Exception as e:  # pylint: disable=broad-except; we really need to catch everything here
            log.exception(e)
            return self.malformed_request()

        # Fail if there are any critical extensions that we do not understand
        for ext in ocsp_req.extensions:
            if ext.critical and not isinstance(ext.value, OCSPNonce):  # pragma: no cover
                # It seems impossible to get cryptography to create such a request, so it's not tested
                return self.malformed_request()

        # Get CA and certificate
        try:
            ca = self.get_ca()
        except CertificateAuthority.DoesNotExist:
            log.error("%s: Certificate Authority could not be found.", self.ca)
            return self.fail()

        cert_serial = int_to_hex(ocsp_req.serial_number)
        try:
            cert = self.get_cert(ca, cert_serial)
        except Certificate.DoesNotExist:
            log.warning("%s: OCSP request for unknown cert received.", cert_serial)
            return self.fail()
        except CertificateAuthority.DoesNotExist:
            log.warning("%s: OCSP request for unknown CA received.", cert_serial)
            return self.fail()

        # get key/cert for OCSP responder
        try:
            responder_key = self.get_responder_key()
            responder_cert = self.get_responder_cert()
        except Exception:  # pylint: disable=broad-except; we really need to catch everything here
            log.error("Could not read responder key/cert.")
            return self.fail()

        # get the certificate status
        if cert.revoked:
            status = ocsp.OCSPCertStatus.REVOKED
        else:
            status = ocsp.OCSPCertStatus.GOOD

        now = datetime.utcnow()
        builder = ocsp.OCSPResponseBuilder()
        expires = datetime.utcnow() + timedelta(seconds=self.expires)
        builder = builder.add_response(
            cert=cert.pub.loaded,
            issuer=ca.pub.loaded,
            algorithm=hashes.SHA1(),
            cert_status=status,
            this_update=now,
            next_update=expires,
            revocation_time=cert.get_revocation_time(),
            revocation_reason=cert.get_revocation_reason(),
        ).responder_id(ocsp.OCSPResponderEncoding.HASH, responder_cert)

        # Add the responder cert to the response, necessary because we (so far) always use delegate
        # certificates
        builder = builder.certificates([responder_cert])

        # Add OCSP nonce if present
        try:
            nonce = ocsp_req.extensions.get_extension_for_class(OCSPNonce)
            builder = builder.add_extension(nonce.value, critical=nonce.critical)
        except ExtensionNotFound:
            pass

        response = builder.sign(responder_key, hashes.SHA256())
        return self.http_response(response.public_bytes(Encoding.DER))


@method_decorator(csrf_exempt, name="dispatch")
class GenericOCSPView(OCSPView):
    """View providing auto-configured OCSP functionality.

    This view assumes that ``ocsp/$ca_serial.(key|pem)`` point to the private/public key of a responder
    certificate as created by :py:class:`~django_ca.tasks.generate_ocsp_keys`. The ``serial`` URL keyword
    argument must be the serial for this CA.
    """

    auto_ca: CertificateAuthority

    def dispatch(  # type: ignore[override]
        self, request: HttpRequest, serial: str, **kwargs: typing.Any
    ) -> "HttpResponseBase":
        if request.method == "GET" and "data" not in kwargs:
            return self.http_method_not_allowed(request, serial, **kwargs)
        if request.method == "POST" and "data" in kwargs:
            return self.http_method_not_allowed(request, serial, **kwargs)
        self.auto_ca = CertificateAuthority.objects.get(serial=serial)
        return super().dispatch(request, **kwargs)

    def get_ca(self) -> CertificateAuthority:
        return self.auto_ca

    def get_responder_key_data(self) -> bytes:
        serial = self.auto_ca.serial.replace(":", "")
        return read_file(f"ocsp/{serial}.key")

    def get_responder_cert(self) -> x509.Certificate:
        serial = self.auto_ca.serial.replace(":", "")
        data = read_file(f"ocsp/{serial}.pem")
        return load_pem_x509_certificate(data)


class GenericCAIssuersView(View):
    """Generic view that returns a CA public key in DER format.

    This view serves the URL named in the ``issuers`` key in the
    :py:class:`~cg:cryptography.x509.AuthorityInformationAccess` extension.
    """

    def get(self, request: HttpRequest, serial: str) -> HttpResponse:
        # pylint: disable=missing-function-docstring; standard Django view function
        ca = CertificateAuthority.objects.get(serial=serial)
        return HttpResponse(ca.pub.der, content_type="application/pkix-cert")
