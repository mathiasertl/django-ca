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

import base64
import binascii
import logging
import os
from datetime import datetime
from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ExtensionNotFound
from cryptography.x509 import OCSPNonce
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509 import ocsp

from django.core.cache import cache
from django.http import HttpResponse
from django.http import HttpResponseServerError
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import View
from django.views.generic.detail import SingleObjectMixin

from . import ca_settings
from .models import Certificate
from .models import CertificateAuthority
from .utils import SERIAL_RE
from .utils import get_crl_cache_key
from .utils import int_to_hex
from .utils import parse_encoding
from .utils import read_file

log = logging.getLogger(__name__)


class CertificateRevocationListView(View, SingleObjectMixin):
    """Generic view that provides Certificate Revocation Lists (CRLs)."""

    slug_field = 'serial'
    slug_url_kwarg = 'serial'
    queryset = CertificateAuthority.objects.all().prefetch_related('certificate_set')

    password = None
    """Password used to load the private key of the certificate authority. If not set, the private key is
    assumed to be unencrypted."""

    # parameters for the CRL itself
    type = Encoding.DER
    """Filetype for CRL."""

    scope = 'user'
    """Set to ``"user"`` to limit CRL to certificates or ``"ca"`` to certificate authorities or ``None`` to
    include both."""

    expires = 600
    """CRL expires in this many seconds."""

    digest = hashes.SHA512()
    """Digest used for generating the CRL."""

    # header used in the request
    content_type = None
    """Value of the Content-Type header used in the response. For CRLs in PEM format, use ``text/plain``."""

    def get(self, request, serial):
        encoding = parse_encoding(request.GET.get('encoding', self.type))
        cache_key = get_crl_cache_key(serial, algorithm=self.digest, encoding=encoding, scope=self.scope)

        crl = cache.get(cache_key)
        if crl is None:
            ca = self.get_object()
            encoding = parse_encoding(self.type)
            crl = ca.get_crl(expires=self.expires, algorithm=self.digest, password=self.password,
                             scope=self.scope)
            crl = crl.public_bytes(encoding)
            cache.set(cache_key, crl, self.expires)

        content_type = self.content_type
        if content_type is None:
            if self.type == Encoding.DER:
                content_type = 'application/pkix-crl'
            elif self.type == Encoding.PEM:
                content_type = 'text/plain'
            else:  # pragma: no cover
                # DER/PEM are all known encoding types, so this shouldn't happen
                return HttpResponseServerError()

        return HttpResponse(crl, content_type=content_type)


@method_decorator(csrf_exempt, name='dispatch')
class OCSPBaseView(View):
    """View to provide an OCSP responder.

    django-ca currently provides two OCSP implementations, one using cryptography>=2.4 and one using oscrypto
    for older versions of cryptography that do not support OCSP. This is a base view that provides some
    generic settings and common functions to both implementations.

    Note that providing the responder key or certificate using an absolute path is deprecated for the Django
    file storage API. Please see :ref:`update-file-storage` for more information.
    """

    ca = None
    """The name or serial of your Certificate Authority."""

    responder_key = None
    """Private key used for signing OCSP responses. Either a relative path used by :ref:`CA_FILE_STORAGE
    <settings-ca-file-storage>` or (**deprecated**) an absolute path on the local filesystem."""

    responder_cert = None
    """Public key of the responder.

    This may either be:

    * A relative path used by :ref:`CA_FILE_STORAGE <settings-ca-file-storage>`
    * **Deprecated:** An absolute path on the local filesystem
    * A serial of a certificate as stored in the database
    * The PEM of the certificate as string
    * A loaded :py:class:`~cg:cryptography.x509.Certificate`
    """

    expires = 600
    """Time in seconds that the responses remain valid. The default is 600 seconds or ten minutes."""

    ca_ocsp = False
    """If set to ``True``, validate child CAs instead."""

    def get(self, request, data):
        try:
            data = base64.b64decode(data)
        except binascii.Error:
            return self.malformed_request()

        try:
            return self.process_ocsp_request(data)
        except Exception as e:
            log.exception(e)
            return self.fail()

    def post(self, request):
        try:
            return self.process_ocsp_request(request.body)
        except Exception as e:
            log.exception(e)
            return self.fail()

    def get_responder_key_data(self):
        if os.path.isabs(self.responder_key):
            log.warning('%s: OCSP responder uses absolute path to private key. Please see %s.',
                        self.responder_key, ca_settings.CA_FILE_STORAGE_URL)

        return read_file(self.responder_key)

    def get_responder_cert_data(self):
        if self.responder_cert.startswith('-----BEGIN CERTIFICATE-----\n'):
            return self.responder_cert.encode('utf-8')

        if SERIAL_RE.match(self.responder_cert):
            serial = self.responder_cert.replace(':', '')
            return Certificate.objects.get(serial=serial).pub.encode('utf-8')

        if os.path.isabs(self.responder_cert):
            log.warning('%s: OCSP responder uses absolute path to certificate. Please see %s.',
                        self.responder_cert, ca_settings.CA_FILE_STORAGE_URL)

        return read_file(self.responder_cert)

    def get_ca(self):
        return CertificateAuthority.objects.get_by_serial_or_cn(self.ca)

    def get_cert(self, ca, serial):
        if self.ca_ocsp is True:
            return CertificateAuthority.objects.filter(parent=ca).get(serial=serial)
        else:
            return Certificate.objects.filter(ca=ca).get(serial=serial)

    def http_response(self, data, status=200):
        return HttpResponse(data, status=status, content_type='application/ocsp-response')


class OCSPView(OCSPBaseView):
    """View providing OCSP functionality.

    Depending on the cryptography version used, this view might use either cryptography or oscrypto."""

    def fail(self, status=ocsp.OCSPResponseStatus.INTERNAL_ERROR):
        return self.http_response(
            ocsp.OCSPResponseBuilder.build_unsuccessful(status).public_bytes(Encoding.DER)
        )

    def malformed_request(self):
        return self.fail(ocsp.OCSPResponseStatus.MALFORMED_REQUEST)

    def get_responder_key(self):
        key = self.get_responder_key_data()
        return serialization.load_pem_private_key(key, None, default_backend())

    def get_responder_cert(self):
        # User configured a loaded certificate
        if isinstance(self.responder_cert, x509.Certificate):
            return self.responder_cert

        responder_cert = self.get_responder_cert_data()
        return load_pem_x509_certificate(responder_cert, default_backend())

    def process_ocsp_request(self, data):
        try:
            ocsp_req = ocsp.load_der_ocsp_request(data)  # NOQA
        except Exception as e:
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
            log.error('%s: Certificate Authority could not be found.', self.ca)
            return self.fail()

        try:
            cert = self.get_cert(ca, int_to_hex(ocsp_req.serial_number))
        except Certificate.DoesNotExist:
            log.warning('OCSP request for unknown cert received.')
            return self.fail()
        except CertificateAuthority.DoesNotExist:
            log.warning('OCSP request for unknown CA received.')
            return self.fail()

        # get key/cert for OCSP responder
        try:
            responder_key = self.get_responder_key()
            responder_cert = self.get_responder_cert()
        except Exception:
            log.error('Could not read responder key/cert.')
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
            cert=cert.x509, issuer=ca.x509, algorithm=hashes.SHA1(),
            cert_status=status,
            this_update=now,
            next_update=expires,
            revocation_time=cert.get_revocation_time(),
            revocation_reason=cert.get_revocation_reason()
        ).responder_id(
            ocsp.OCSPResponderEncoding.HASH, responder_cert
        )

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


@method_decorator(csrf_exempt, name='dispatch')
class GenericOCSPView(OCSPView):
    def dispatch(self, request, serial, **kwargs):
        if request.method == 'GET' and 'data' not in kwargs:
            return self.http_method_not_allowed(request, serial, **kwargs)
        elif request.method == 'POST' and 'data' in kwargs:
            return self.http_method_not_allowed(request, serial, **kwargs)
        self.ca = CertificateAuthority.objects.get(serial=serial)
        return super(GenericOCSPView, self).dispatch(request, **kwargs)

    def get_ca(self):
        return self.ca

    def get_responder_key_data(self):
        return read_file('ocsp/%s.key' % self.ca.serial.replace(':', ''))

    def get_responder_cert_data(self):
        return read_file('ocsp/%s.pem' % self.ca.serial.replace(':', ''))


class GenericCAIssuersView(View):
    def get(self, request, serial):
        ca = CertificateAuthority.objects.get(serial=serial)
        data = ca.x509.public_bytes(encoding=Encoding.DER)
        return HttpResponse(data, content_type='application/pkix-cert')
