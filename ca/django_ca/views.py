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

from datetime import timedelta

import asn1crypto

from OpenSSL import crypto
from ocspbuilder import OCSPResponseBuilder
from oscrypto.asymmetric import load_certificate
from oscrypto.asymmetric import load_private_key

from django.core.cache import cache
from django.core.urlresolvers import reverse
from django.http import HttpResponse
from django.utils import timezone
from django.utils.decorators import classonlymethod
from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import View
from django.views.generic.detail import SingleObjectMixin
from django.views.generic.edit import UpdateView

from .crl import get_crl
from .forms import RevokeCertificateForm
from .models import Certificate
from .models import CertificateAuthority
from .utils import serial_from_int

log = logging.getLogger(__name__)


class CertificateRevocationListView(View, SingleObjectMixin):
    """Generic view that provides Certificate Revocation Lists (CRLs)."""

    slug_field = 'serial'
    slug_url_kwarg = 'serial'
    queryset = CertificateAuthority.objects.all().prefetch_related('certificate_set')

    # parameters for the CRL itself
    type = crypto.FILETYPE_ASN1
    """Filetype for CRL, one of the ``OpenSSL.crypto.FILETYPE_*`` variables. The default is
    ``OpenSSL.crypto.FILETYPE_ASN1``."""

    expires = 600
    """CRL expires in this many seconds."""

    digest = 'sha512'
    """Digest used for generating the CRL."""

    # header used in the request
    content_type = 'application/pkix-crl'
    """The value of the Content-Type header used in the response. For CRLs in
    PEM format, use ``"text/plain"``."""

    def get(self, request, serial):
        cache_key = 'crl_%s_%s_%s' % (serial, self.type, self.digest)
        crl = cache.get(cache_key)
        if crl is None:
            ca = self.get_object()
            crl = get_crl(ca, type=self.type, expires=self.expires, digest=force_bytes(self.digest))
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
    ca_serial = None
    responder_key = None
    responder_cert = None

    @classonlymethod
    def as_view(cls, **kwargs):
        kwargs['responder_key'] = load_private_key(kwargs['responder_key'])
        return super(OCSPView, cls).as_view(**kwargs)

    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super(OCSPView, self).dispatch(*args, **kwargs)

    def get(self, request, data):
        return self.process_ocsp_request(base64.b64decode(data))

    def post(self, request):
        return self.process_ocsp_request(request.body)

    def get_responder_cert(self):
        try:
            pub = force_bytes(Certificate.objects.get(serial=self.responder_cert).pub)
        except Certificate.DoesNotExist:
            with open(self.responder_cert, 'rb') as stream:
                pub = stream.read()
        return load_certificate(pub)

    def fail(self, reason):
        builder = OCSPResponseBuilder(response_status=reason)
        return builder.build()

    def process_ocsp_request(self, data):
        try:
            response = self.get_ocsp_response(data)
        except:
            response = self.fail('internal_error')

        return HttpResponse(response.dump(), content_type='application/ocsp-response')

    def get_ocsp_response(self, data):
        ocsp_request = asn1crypto.ocsp.OCSPRequest.load(data)

        tbs_request = ocsp_request['tbs_request']
        request_list = tbs_request['request_list']
        if len(request_list) != 1:
            print('Received OCSP request with multiple sub requests')
            raise NotImplemented('Combined requests not yet supported')
        single_request = request_list[0]  # TODO: Support more than one request
        req_cert = single_request['req_cert']
        serial = serial_from_int(req_cert['serial_number'].native)

        ca = CertificateAuthority.objects.get(serial=self.ca_serial)

        try:
            cert = Certificate.objects.filter(ca=ca).get(serial=serial)
        except Certificate.DoesNotExist:
            return self.fail('internal_error')  # TODO: return a 'unkown' response instead

        builder = OCSPResponseBuilder(
            response_status='successful',  # ResponseStatus.successful.value,
            certificate=load_certificate(force_bytes(cert.pub)),
            certificate_status=cert.ocsp_status,
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
            else:
                unknown = True

            # If an unknown critical extension is encountered (which should not
            # usually happen, according to RFC 6960 4.1.2), we should throw our
            # hands up in despair and run.
            if unknown is True and critical is True:
                log.warning('Could not parse unknown critical extension: %r',
                        dict(extension.native))
#                return self._fail(ResponseStatus.internal_error)

            # If it's an unknown non-critical extension, we can safely ignore it.
            elif unknown is True:
                log.info('Ignored unknown non-critical extension: %r', dict(extension.native))

        builder.certificate_issuer = load_certificate(force_bytes(ca.pub))
        builder.next_update = timezone.now() + timedelta(days=1)

        responder_cert = self.get_responder_cert()

        return builder.build(self.responder_key, responder_cert)
