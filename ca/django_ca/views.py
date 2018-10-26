# -*- coding: utf-8 -*-
#
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
import logging
import os
from datetime import datetime
from datetime import timedelta

import asn1crypto
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from ocspbuilder import OCSPResponseBuilder
from oscrypto.asymmetric import load_certificate
from oscrypto.asymmetric import load_private_key

from django.core.cache import cache
from django.http import HttpResponse
from django.http import HttpResponseServerError
from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes
from django.utils.encoding import force_text
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import View
from django.views.generic.detail import SingleObjectMixin

from .crl import get_crl
from .models import Certificate
from .models import CertificateAuthority
from .utils import int_to_hex

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

    ca_crl = False
    """If set to ``True``, return a CRL for child CAs instead."""

    expires = 600
    """CRL expires in this many seconds."""

    digest = hashes.SHA512()
    """Digest used for generating the CRL."""

    # header used in the request
    content_type = None
    """Value of the Content-Type header used in the response. For CRLs in PEM format, use ``text/plain``."""

    def get(self, request, serial):
        cache_key = 'crl_%s_%s_%s' % (serial, self.type, self.digest.name)
        if self.ca_crl is True:
            cache_key += '_ca'

        crl = cache.get(cache_key)
        if crl is None:
            ca = self.get_object()
            crl = get_crl(ca, encoding=self.type, expires=self.expires, algorithm=self.digest,
                          password=self.password, ca_crl=self.ca_crl)
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


class OCSPView(View):
    """View to provide an OCSP responder.

    .. seealso::

        This is heavily inspired by
        https://github.com/threema-ch/ocspresponder/blob/master/ocspresponder/__init__.py.
    """
    ca = None
    """The name or serial of your Certificate Authority."""

    responder_key = None
    """Absolute path to the private key used for signing OCSP responses."""

    responder_cert = None
    """Absolute path to the public key used for signing OCSP responses. May also be a serial identifying a
    certificate from the database."""

    expires = 600
    """Time in seconds that the responses remain valid. The default is 600 seconds or ten minutes."""

    ca_ocsp = False
    """If set to ``True``, validate child CAs instead."""

    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super(OCSPView, self).dispatch(*args, **kwargs)

    def get(self, request, data):
        return self.process_ocsp_request(base64.b64decode(data))

    def post(self, request):
        return self.process_ocsp_request(request.body)

    def fail(self, reason):
        builder = OCSPResponseBuilder(response_status=reason)
        return builder.build()

    def process_ocsp_request(self, data):
        status = 200
        try:
            response = self.get_ocsp_response(data)
        except Exception as e:  # pragma: no cover
            # all exceptions in the function should be covered.
            log.exception(e)
            response = self.fail(u'internal_error')
            status = 500

        return HttpResponse(response.dump(), status=status,
                            content_type='application/ocsp-response')

    def get_responder_key(self):
        with open(self.responder_key, 'rb') as stream:
            responder_key = stream.read()

        # try to load responder key and cert with oscrypto, to make sure they are actually usable
        return load_private_key(responder_key)

    def get_responder_cert(self):
        if os.path.exists(self.responder_cert):
            with open(self.responder_cert, 'rb') as stream:
                responder_cert = stream.read()
        else:
            responder_cert = Certificate.objects.get(serial=self.responder_cert)

        return load_certificate(responder_cert)

    def get_ocsp_response(self, data):
        try:
            ocsp_request = asn1crypto.ocsp.OCSPRequest.load(data)

            tbs_request = ocsp_request['tbs_request']
            request_list = tbs_request['request_list']
            if len(request_list) != 1:
                log.error('Received OCSP request with multiple sub requests')
                raise NotImplementedError('Combined requests not yet supported')
            single_request = request_list[0]  # TODO: Support more than one request
            req_cert = single_request['req_cert']
            serial = int_to_hex(req_cert['serial_number'].native)
        except Exception as e:
            log.exception('Error parsing OCSP request: %s', e)
            return self.fail(u'malformed_request')

        # Get CA and certificate
        try:
            ca = CertificateAuthority.objects.get_by_serial_or_cn(self.ca)
        except CertificateAuthority.DoesNotExist:
            log.error('%s: Certificate Authority could not be found.')
            return self.fail(u'internal_error')

        if self.ca_ocsp is True:
            try:
                cert = CertificateAuthority.objects.filter(parent=ca).get(serial=serial)
            except CertificateAuthority.DoesNotExist:
                log.warning('OCSP request for unknown CA received.')
                return self.fail(u'internal_error')
        else:
            try:
                cert = Certificate.objects.filter(ca=ca).get(serial=serial)
            except Certificate.DoesNotExist:
                log.warning('OCSP request for unknown cert received.')
                return self.fail(u'internal_error')

        # load ca cert and responder key/cert
        try:
            ca_cert = load_certificate(force_bytes(ca.pub))
        except Exception:
            log.error('Could not load CA certificate.')
            return self.fail(u'internal_error')

        try:
            responder_key = self.get_responder_key()
            responder_cert = self.get_responder_cert()
        except Exception:
            log.error('Could not read responder key/cert.')
            return self.fail(u'internal_error')

        builder = OCSPResponseBuilder(
            response_status=u'successful',  # ResponseStatus.successful.value,
            certificate=load_certificate(force_bytes(cert.pub)),
            certificate_status=force_text(cert.ocsp_status),
            revocation_date=cert.revoked_date,
        )

        # Parse extensions
        for extension in tbs_request['request_extensions']:
            extn_id = extension['extn_id'].native
            critical = extension['critical'].native
            value = extension['extn_value'].parsed

            # This variable tracks whether any unknown extensions were encountered
            unknown = False

            # Handle nonce extension
            if extn_id == 'nonce':
                builder.nonce = value.native

            # That's all we know
            else:  # pragma: no cover
                unknown = True

            # If an unknown critical extension is encountered (which should not
            # usually happen, according to RFC 6960 4.1.2), we should throw our
            # hands up in despair and run.
            if unknown is True and critical is True:  # pragma: no cover
                log.warning('Could not parse unknown critical extension: %r',
                            dict(extension.native))
                return self._fail('internal_error')

            # If it's an unknown non-critical extension, we can safely ignore it.
            elif unknown is True:  # pragma: no cover
                log.info('Ignored unknown non-critical extension: %r', dict(extension.native))

        builder.certificate_issuer = ca_cert
        builder.next_update = datetime.utcnow() + timedelta(seconds=self.expires)
        return builder.build(responder_key, responder_cert)
