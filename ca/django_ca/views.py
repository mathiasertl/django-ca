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

from OpenSSL import crypto

from django.core.cache import cache
from django.core.urlresolvers import reverse
from django.http import HttpResponse
from django.utils.encoding import force_bytes
from django.views.generic.base import View
from django.views.generic.detail import SingleObjectMixin
from django.views.generic.edit import UpdateView

from .crl import get_crl
from .forms import RevokeCertificateForm
from .models import Certificate
from .models import CertificateAuthority


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
