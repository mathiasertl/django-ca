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
import typing
import warnings
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from typing import Any, cast

from pydantic import BaseModel

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import (
    ExtensionNotFound,
    OCSPNonce,
    load_der_x509_certificate,
    load_pem_x509_certificate,
    ocsp,
)
from cryptography.x509.ocsp import OCSPResponse, OCSPResponseBuilder

from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest, HttpResponseServerError
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import View

from django_ca import constants
from django_ca.constants import CERTIFICATE_REVOCATION_LIST_ENCODING_TYPES
from django_ca.deprecation import RemovedInDjangoCA270Warning
from django_ca.models import Certificate, CertificateAuthority, CertificateRevocationList
from django_ca.pydantic.validators import crl_scope_validator
from django_ca.querysets import CertificateRevocationListQuerySet
from django_ca.typehints import CertificateRevocationListEncoding, SignatureHashAlgorithm
from django_ca.utils import SERIAL_RE, get_crl_cache_key, int_to_hex, parse_encoding, read_file

log = logging.getLogger(__name__)

if typing.TYPE_CHECKING:
    from django.http.response import HttpResponseBase


class CertificateRevocationListView(View):
    """Generic view that provides Certificate Revocation Lists (CRLs)."""

    # parameters for the CRL itself
    type: CertificateRevocationListEncoding = Encoding.DER
    """Encoding for CRL."""

    only_contains_ca_certs: bool = False
    """Set to ``True`` to only include CA certificates in the CRL."""

    only_contains_user_certs: bool = False
    """Set to ``True`` to only include end-entity certificates in the CRL."""

    only_contains_attribute_certs: bool = False
    """Set to ``True`` to only include attribute certificates in the CRL."""

    only_some_reasons: frozenset[x509.ReasonFlags] | None = None
    """Only include certificates revoked for one of the given :class:`~cg:cryptography.x509.ReasonFlags`. If
    not set, all reasons are included."""

    expires = 86400
    """**(deprecated)** CRL not_after in this many seconds.

    *Please note* that this value is only used if no current CRL is found in the database (or cache) and the
    CRL is generated locally (which will fail if the view does not have access to the private key).

    .. versionchanged:: 2.1.0

       The default was changed to one day (from 600) to align with the default elsewhere in the code.
    """

    # header used in the request
    content_type = None
    """Value of the Content-Type header used in the response. For CRLs in PEM format, use ``text/plain``."""

    def get_key_backend_options(self, ca: CertificateAuthority) -> BaseModel:
        """Method to get the key backend options to access the private key.

        If a custom CA backend needs transient parameters (e.g. passwords), a view overriding this method
        must be implemented.
        """
        return ca.key_backend.get_use_private_key_options(ca, {})

    def fetch_crl(self, serial: str, encoding: CertificateRevocationListEncoding) -> bytes:
        """Actually fetch the CRL (nested function so that we can easily catch any exception)."""
        crl_scope_validator(
            only_contains_ca_certs=self.only_contains_ca_certs,
            only_contains_user_certs=self.only_contains_user_certs,
            only_contains_attribute_certs=self.only_contains_attribute_certs,
            only_some_reasons=self.only_some_reasons,
        )

        cache_key = get_crl_cache_key(
            serial,
            encoding=encoding,
            only_contains_ca_certs=self.only_contains_ca_certs,
            only_contains_user_certs=self.only_contains_user_certs,
            only_contains_attribute_certs=self.only_contains_attribute_certs,
            only_some_reasons=self.only_some_reasons,
        )

        encoded_crl: bytes | None = cache.get(cache_key)

        # CRL is not cached, try to retrieve it from the database.
        if encoded_crl is None:
            now = timezone.now()

            crl_qs: CertificateRevocationListQuerySet = (
                CertificateRevocationList.objects.scope(
                    serial=serial,
                    only_contains_ca_certs=self.only_contains_ca_certs,
                    only_contains_user_certs=self.only_contains_user_certs,
                    only_contains_attribute_certs=self.only_contains_attribute_certs,
                    only_some_reasons=self.only_some_reasons,
                )
                .exclude(next_update__lt=now)
                .exclude(last_update__gt=now)
                .filter(data__isnull=False)  # Only objects that have CRL data associated with it
            )
            crl_obj: CertificateRevocationList | None = crl_qs.newest()

            # CRL was not found in the database either, so we try to regenerate it.
            if crl_obj is None:
                ca: CertificateAuthority = CertificateAuthority.objects.get(serial=serial)

                key_backend_options = self.get_key_backend_options(ca)
                expires = now + timedelta(seconds=self.expires)
                crl_obj = CertificateRevocationList.objects.create_certificate_revocation_list(
                    ca=ca,
                    key_backend_options=key_backend_options,
                    next_update=expires,
                    only_contains_ca_certs=self.only_contains_ca_certs,
                    only_contains_user_certs=self.only_contains_user_certs,
                    only_contains_attribute_certs=self.only_contains_attribute_certs,
                    only_some_reasons=self.only_some_reasons,
                )

            # Cache the CRL.
            crl_obj.cache(serial)

            # Get object in the right encoding.
            if encoding == Encoding.PEM:
                encoded_crl = crl_obj.pem
            else:
                encoded_crl = bytes(crl_obj.data)  # type: ignore[arg-type]  # None is ruled out by filter()

        return encoded_crl

    def get(self, request: HttpRequest, serial: str) -> HttpResponse:
        # pylint: disable=missing-function-docstring; standard Django view function
        if get_encoding := request.GET.get("encoding"):
            if get_encoding not in CERTIFICATE_REVOCATION_LIST_ENCODING_TYPES:
                return HttpResponseBadRequest("Invalid encoding requested.", content_type="text/plain")
            # TYPEHINT NOTE: type is verified in the previous line
            encoding = cast(CertificateRevocationListEncoding, parse_encoding(get_encoding))
        else:
            encoding = self.type

        try:
            crl = self.fetch_crl(serial, encoding)
        except Exception:  # pylint: disable=broad-exception-caught
            log.exception("Error generating a CRL")
            return HttpResponseServerError("Error while retrieving the CRL.", content_type="text/plain")

        content_type = self.content_type
        if content_type is None:
            if encoding == Encoding.DER:
                content_type = "application/pkix-crl"
            elif encoding == Encoding.PEM:
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
    """Private key used for signing OCSP responses. A relative path used by the storage backend configured by
    :ref:`CA_DEFAULT_STORAGE_ALIAS <settings-ca-default-storage-alias>`."""

    responder_cert: x509.Certificate | str = ""
    """Public key of the responder.

    This may either be:

    * A serial of a certificate as stored in the database
    * The PEM of the certificate as string
    * A loaded :py:class:`~cg:cryptography.x509.Certificate`
    """

    expires: timedelta = timedelta(seconds=600)
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

    def get_responder_key(self) -> CertificateIssuerPrivateKeyTypes:
        """Get the private key used to sign OCSP responses."""
        key = self.get_responder_key_data()

        try:
            loaded_key = serialization.load_der_private_key(key, None)
        except ValueError:
            try:
                loaded_key = serialization.load_pem_private_key(key, None)
            except ValueError as ex:
                raise ValueError("Could not decrypt private key.") from ex

        # Check that the private key is of a supported type
        if not isinstance(loaded_key, constants.PRIVATE_KEY_TYPES):
            log.error("%s: Unsupported private key type.", type(loaded_key))
            raise ValueError(f"{type(loaded_key)}: Unsupported private key type.")

        return loaded_key  # type: ignore[return-value]  # mypy not smart enough for above isinstance() check

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
            cert = Certificate.objects.get(serial=serial)
            return cert.pub.loaded
        else:
            responder_cert = read_file(self.responder_cert)

        try:
            return load_der_x509_certificate(responder_cert)
        except ValueError:
            return load_pem_x509_certificate(responder_cert)

    def get_ca(self) -> CertificateAuthority:
        """Get the certificate authority for the request."""
        return CertificateAuthority.objects.get_by_serial_or_cn(self.ca)

    def get_cert(self, ca: CertificateAuthority, serial: str) -> Certificate | CertificateAuthority:
        """Get the certificate that was requested in the OCSP request."""
        if self.ca_ocsp is True:
            return CertificateAuthority.objects.filter(parent=ca).get(serial=serial)

        return Certificate.objects.filter(ca=ca).get(serial=serial)

    def get_ocsp_response(  # pylint: disable-next=unused-argument  # ca is required by subclasses
        self, ca: CertificateAuthority, builder: OCSPResponseBuilder
    ) -> HttpResponse | OCSPResponse:
        """Sign the OCSP request using cryptography keys."""
        # get key/cert for OCSP responder
        try:
            responder_key = self.get_responder_key()
            responder_cert = self.get_responder_cert()
        except Exception as ex:
            raise ValueError(f"Could not read responder key/cert: {ex}") from ex

        # Set the responder certificate as signer of the response
        builder = builder.responder_id(ocsp.OCSPResponderEncoding.HASH, responder_cert)
        builder = builder.certificates([responder_cert])

        # The hash algorithm may be different from the signature hash algorithm of the responder certificate,
        # but must be None for Ed448/Ed25519 certificates. Since delegate certificates are ephemeral anyway,
        # configuring the hash algorithm is not supported, instead the user is expected to generate new keys
        # with a different private key type or hash algorithm if desired.
        return builder.sign(responder_key, responder_cert.signature_hash_algorithm)

    # pylint: disable-next=unused-argument  # ca is required by subclasses
    def get_expires(self, ca: CertificateAuthority, now: datetime) -> datetime:
        """Get the timestamp when the OCSP response expires."""
        expires = self.expires
        if isinstance(expires, int):
            warnings.warn(
                "Passing `int` for `expires` is deprecated.", RemovedInDjangoCA270Warning, stacklevel=1
            )
            expires = timedelta(seconds=expires)
        return now + expires

    def http_response(self, data: bytes, status: int = HTTPStatus.OK) -> HttpResponse:
        """Get an HTTP OCSP response with given status and data."""
        return HttpResponse(data, status=status, content_type="application/ocsp-response")

    def malformed_request(self) -> HttpResponse:
        """Get a response for a malformed request."""
        return self.fail(ocsp.OCSPResponseStatus.MALFORMED_REQUEST)

    def get_ca_and_cert(
        self, cert_serial: str
    ) -> tuple[CertificateAuthority, Certificate | CertificateAuthority]:
        """Get CA and certificate for this request."""
        ca = self.get_ca()
        cert = self.get_cert(ca, cert_serial)
        return ca, cert

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

        cert_serial = int_to_hex(ocsp_req.serial_number)

        # NOINSPECTION NOTE: PyCharm wrongly things that second except is already covered by the first.
        # noinspection PyExceptClausesOrder
        try:
            ca, cert = self.get_ca_and_cert(cert_serial)
        except CertificateAuthority.DoesNotExist:
            log.warning("%s: OCSP request for unknown CA received.", cert_serial)
            return self.fail()
        except Certificate.DoesNotExist:
            log.warning("%s: OCSP request for unknown cert received.", cert_serial)
            return self.fail()

        # get the certificate status
        if cert.revoked:
            status = ocsp.OCSPCertStatus.REVOKED
        else:
            status = ocsp.OCSPCertStatus.GOOD

        now = datetime.now(tz=UTC)
        builder = ocsp.OCSPResponseBuilder()
        expires = self.get_expires(ca, now)
        builder = builder.add_response(
            cert=cert.pub.loaded,
            issuer=ca.pub.loaded,
            # The algorithm used must be the same as in the request, or "openssl ocsp" won't be able to
            # determine the status (verified: NOT the hash algorithm of the requested certificate).
            algorithm=ocsp_req.hash_algorithm,
            cert_status=status,
            this_update=now.replace(tzinfo=None),
            next_update=expires,
            revocation_time=cert.get_revocation_time(),
            revocation_reason=cert.get_revocation_reason(),
        )

        # Add OCSP nonce if present
        try:
            nonce = ocsp_req.extensions.get_extension_for_class(OCSPNonce)
            builder = builder.add_extension(nonce.value, critical=nonce.critical)
        except ExtensionNotFound:
            pass

        # Get the signed OCSP response.
        try:
            response = self.get_ocsp_response(ca, builder)
        except Exception as ex:  # pylint: disable=broad-exception-caught
            log.exception(ex)
            return self.fail()

        if isinstance(response, HttpResponse):
            return response

        return self.http_response(response.public_bytes(Encoding.DER))


@method_decorator(csrf_exempt, name="dispatch")
class GenericOCSPView(OCSPView):
    """View providing auto-configured OCSP functionality.

    This view loads the responder certificate via the OCSP key backend.  The ``serial`` URL keyword
    argument must be the serial for this CA.
    """

    # NOINSPECTION NOTE: It's okay to be more specific here
    # noinspection PyMethodOverriding
    def dispatch(self, request: HttpRequest, serial: str, **kwargs: Any) -> "HttpResponseBase":
        if request.method == "GET" and "data" not in kwargs:
            return self.http_method_not_allowed(request, serial, **kwargs)
        if request.method == "POST" and "data" in kwargs:
            return self.http_method_not_allowed(request, serial, **kwargs)

        # COVERAGE NOTE: Checking just for safety here.
        if not isinstance(serial, str):  # pragma: no cover
            raise ImproperlyConfigured("View expects a str for a serial")

        return super().dispatch(request, **kwargs)

    def get_ca_and_cert(
        self, cert_serial: str
    ) -> tuple[CertificateAuthority, Certificate | CertificateAuthority]:
        ca_serial = self.kwargs["serial"]

        if self.ca_ocsp:
            cert_qs = CertificateAuthority.objects.select_related("parent")
            queried_ca = cert_qs.get(parent__serial=ca_serial, serial=cert_serial)
            parent = cast(CertificateAuthority, queried_ca.parent)  # parent cannot be None due to filter()
            return parent, queried_ca

        cert = Certificate.objects.select_related("ca").get(ca__serial=ca_serial, serial=cert_serial)
        return cert.ca, cert

    def get_expires(self, ca: CertificateAuthority, now: datetime) -> datetime:
        return now + timedelta(seconds=ca.ocsp_response_validity)

    def get_ocsp_response(
        self, ca: CertificateAuthority, builder: OCSPResponseBuilder
    ) -> HttpResponse | OCSPResponse:
        """Sign the OCSP request using cryptography keys."""
        # Load public key
        try:
            responder_pem = ca.ocsp_key_backend_options["certificate"]["pem"]
        except KeyError:
            # The OCSP responder certificate has never been created. `manage.py init_ca` usually creates them,
            # so this can only happen if the system is misconfigured (e.g. Celery task is never acted upon),
            # or the CA was created using the Python API.
            log.error("OCSP responder certificate not found, please regenerate it.")
            return self.fail()

        responder_certificate = x509.load_pem_x509_certificate(responder_pem.encode("ascii"))

        now = datetime.now(tz=UTC)
        if not (
            responder_certificate.not_valid_before_utc <= now <= responder_certificate.not_valid_after_utc
        ):
            log.error("OCSP responder certificate is not currently valid. Please regenerate it.")
            return self.fail()

        # Set the responder certificate as signer of the response
        builder = builder.responder_id(ocsp.OCSPResponderEncoding.HASH, responder_certificate)
        builder = builder.certificates([responder_certificate])

        # TYPEHINT NOTE: Certificates are always generated with a supported algorithm, so we do not check.
        algorithm = cast(SignatureHashAlgorithm | None, responder_certificate.signature_hash_algorithm)

        return ca.ocsp_key_backend.sign_ocsp_response(ca, builder, algorithm)


class GenericCAIssuersView(View):
    """Generic view that returns a CA public key in DER format.

    This view serves the URL named in the ``issuers`` key in the
    :py:class:`~cg:cryptography.x509.AuthorityInformationAccess` extension.
    """

    def get(self, request: HttpRequest, serial: str) -> HttpResponse:
        # pylint: disable=missing-function-docstring; standard Django view function
        cache_key = f"ca_{serial}_der"
        der = cache.get(cache_key)
        if der is None:
            ca = CertificateAuthority.objects.only("pub").get(serial=serial)
            der = ca.pub.der
            cache.set(cache_key, der, timeout=86400)

        return HttpResponse(der, content_type="application/pkix-cert")
