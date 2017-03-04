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
from django.core.exceptions import ImproperlyConfigured
from django.core.urlresolvers import reverse
from django.http import HttpResponse
from django.utils import six
from django.utils.decorators import classonlymethod
from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes
from django.utils.encoding import force_text
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import View
from django.views.generic.detail import SingleObjectMixin
from django.views.generic.edit import UpdateView

from .crl import get_crl
from .forms import RevokeCertificateForm
from .models import Certificate
from .models import CertificateAuthority
from .utils import int_to_hex

log = logging.getLogger(__name__)


class CertificateRevocationListView(View, SingleObjectMixin):
    """Generic view that provides Certificate Revocation Lists (CRLs)."""

    slug_field = 'serial'
    slug_url_kwarg = 'serial'
    queryset = CertificateAuthority.objects.all().prefetch_related('certificate_set')

    # parameters for the CRL itself
    type = Encoding.DER
    """Filetype for CRL, one of the ``OpenSSL.crypto.FILETYPE_*`` variables. The default is
    ``OpenSSL.crypto.FILETYPE_ASN1``."""

    expires = 600
    """CRL expires in this many seconds."""

    digest = hashes.SHA512()
    """Digest used for generating the CRL."""

    # header used in the request
    content_type = 'application/pkix-crl'
    """The value of the Content-Type header used in the response. For CRLs in
    PEM format, use ``"text/plain"``."""

    def get(self, request, serial):
        cache_key = 'crl_%s_%s_%s' % (serial, self.type, self.digest.name)
        crl = cache.get(cache_key)
        if crl is None:
            ca = self.get_object()
            crl = get_crl(ca, encoding=self.type, expires=self.expires, algorithm=self.digest)
            cache.set(cache_key, crl, self.expires)

        return HttpResponse(crl, content_type=self.content_type)


class RevokeCertificateView(UpdateView):
    admin_site = None
    queryset = Certificate.objects.filter(revoked=False)
    form_class = RevokeCertificateForm
    template_name = 'django_ca/admin/certificate_revoke_form.html'

    def get_context_data(self, **kwargs):
        context = super(RevokeCertificateView, self).get_context_data(**kwargs)
        context.update(self.admin_site.each_context(self.request))
        context['opts'] = self.queryset.model._meta  # required by breadcrumbs
        return context

    def form_valid(self, form):
        reason = form.cleaned_data['revoked_reason'] or None
        form.instance.revoke(reason=reason)

        return super(RevokeCertificateView, self).form_valid(form)

    def get_success_url(self):
        meta = self.queryset.model._meta
        return reverse('admin:%s_%s_change' % (meta.app_label, meta.verbose_name),
                       args=(self.object.pk, ))


class OCSPView(View):
    """View to provide an OCSP responder.

    .. seealso:: This is heavily inspired by
        https://github.com/threema-ch/ocspresponder/blob/master/ocspresponder/__init__.py.
    """
    ca = None
    """The serial of your certificate authority."""

    responder_key = None
    """Absolute path to the private key used for signing OCSP responses."""

    responder_cert = None
    """Absolute path, serial of the public key or key itself used for signing OCSP responses."""

    expires = 600
    """Time in seconds that the responses remain valid. The default is 600 seconds or ten
    minutes."""

    @classonlymethod
    def as_view(cls, responder_key, responder_cert, **kwargs):
        # Preload the responder key and certificate for faster access.

        try:
            with open(responder_key, 'rb') as stream:
                responder_key = stream.read()
        except:
            raise ImproperlyConfigured('%s: Could not read private key.' % responder_key)

        if os.path.exists(responder_cert):
            with open(responder_cert, 'rb') as stream:
                responder_cert = stream.read()
        elif isinstance(responder_cert, six.string_types) and len(responder_cert) == 47:
            try:
                cert = Certificate.objects.get(serial=responder_cert)
                responder_cert = force_bytes(cert.pub)
            except Certificate.DoesNotExist:
                pass

        if not responder_cert:
            raise ImproperlyConfigured('%s: Could not read public key.' % responder_cert)

        return super(OCSPView, cls).as_view(
            responder_key=responder_key, responder_cert=responder_cert, **kwargs)

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
        except Exception as e:
            log.exception(e)
            response = self.fail(u'internal_error')
            status = 500

        return HttpResponse(response.dump(), status=status,
                            content_type='application/ocsp-response')

    def get_ocsp_response(self, data):
        try:
            ocsp_request = asn1crypto.ocsp.OCSPRequest.load(data)

            tbs_request = ocsp_request['tbs_request']
            request_list = tbs_request['request_list']
            if len(request_list) != 1:
                log.error('Received OCSP request with multiple sub requests')
                raise NotImplemented('Combined requests not yet supported')
            single_request = request_list[0]  # TODO: Support more than one request
            req_cert = single_request['req_cert']
            serial = int_to_hex(req_cert['serial_number'].native)
        except Exception as e:
            log.exception('Error parsing OCSP request: %s', e)
            return self.fail(u'malformed_request')

        # Get CA and certificate
        ca = CertificateAuthority.objects.get(serial=self.ca)
        try:
            cert = Certificate.objects.filter(ca=ca).get(serial=serial)
        except Certificate.DoesNotExist:
            log.warn('OCSP request for unknown cert received.')
            return self.fail(u'internal_error')

        # load ca cert and responder key/cert
        ca_cert = load_certificate(force_bytes(ca.pub))
        responder_key = load_private_key(self.responder_key)
        responder_cert = load_certificate(self.responder_cert)

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
