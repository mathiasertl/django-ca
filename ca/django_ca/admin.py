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

import json

from OpenSSL import crypto

from django.conf.urls import url
from django.contrib import admin
from django.http import HttpResponse
from django.http import HttpResponseBadRequest
from django.template.response import TemplateResponse
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _

from .crl import write_crl
from .forms import CreateCertificateForm
from .models import Certificate
from .models import CertificateAuthority
from .models import Watcher
from .ocsp import write_index
from .utils import get_cert
from .views import RevokeCertificateView

_x509_ext_fields = [
    'keyUsage', 'extendedKeyUsage', 'subjectKeyIdentifier', 'issuerAltName',
    'authorityKeyIdentifier', 'crlDistributionPoints', 'authorityInfoAccess', ]


@admin.register(Watcher)
class WatcherAdmin(admin.ModelAdmin):
    pass


@admin.register(CertificateAuthority)
class CertificateAuthorityAdmin(admin.ModelAdmin):
    fieldsets = (
        (None, {
            'fields': ['name', 'enabled', 'parent', 'subjectKeyIdentifier', 'authorityInfoAccess',
                       'issuerAltName', 'authorityKeyIdentifier'],
        }),
        (_('Certificate'), {
            'fields': ['serial', 'pub', ],
            # The "as-code" class is used so CSS can only match this section (and only in an
            # existing cert).
            'classes': ('as-code', ),
        }),
    )
    list_display = ['enabled', 'name', 'serial', ]
    list_display_links = ['enabled', 'name', ]
    search_fields = ['cn', 'name', 'serial', ]
    readonly_fields = ['serial', 'pub', 'parent', 'subjectKeyIdentifier', 'issuerAltName',
                       'authorityKeyIdentifier', 'authorityInfoAccess']

    def has_add_permission(self, request):
        return False

    def get_urls(self):
        # Remove the delete action from the URLs
        urls = super(CertificateAuthorityAdmin, self).get_urls()
        add_name = '%s_%s_add' % (self.model._meta.app_label, self.model._meta.model_name)
        return [u for u in urls if u.name != add_name]

    class Media:
        css = {
            'all': (
                'django_ca/admin/css/certificateauthorityadmin.css',
                'django_ca/admin/css/monospace.css',
            ),
        }


class StatusListFilter(admin.SimpleListFilter):
    title = _('Status')
    parameter_name = 'status'

    def lookups(self, request, model_admin):
        return (
            ('valid', _('Valid')),
            ('expired', _('Expired')),
            ('revoked', _('Revoked')),
        )

    def queryset(self, request, queryset):
        if self.value() == 'valid':
            return queryset.valid()
        elif self.value() == 'expired':
            return queryset.expired()
        elif self.value() == 'revoked':
            return queryset.revoked()


@admin.register(Certificate)
class CertificateAdmin(admin.ModelAdmin):
    actions = ['revoke', ]
    change_form_template = 'django_ca/admin/change_form.html'
    list_display = ('cn', 'serial', 'status', 'expires_date')
    list_filter = (StatusListFilter, 'ca')
    readonly_fields = [
        'expires', 'csr', 'pub', 'cn', 'serial', 'revoked', 'revoked_date', 'revoked_reason',
        'subjectAltName', 'distinguishedName', 'ca', ] + _x509_ext_fields
    search_fields = ['cn', 'serial', ]

    fieldsets = [
        (None, {
            'fields': ['cn', 'subjectAltName', 'distinguishedName', 'serial', 'ca', 'expires',
                       'watchers', ],
        }),
        (_('X509 Extensions'), {
            'fields': _x509_ext_fields,
            'classes': ('collapse', ),
        }),
        (_('Revocation'), {
            'fields': ('revoked', 'revoked_date', 'revoked_reason', ),
        }),
        (_('Certificate'), {
            'fields': ['pub', 'csr', ],
            # The "as-code" class is used so CSS can only match this section (and only in an
            # existing cert).
            'classes': ('collapse', 'as-code'),
        }),
    ]
    add_fieldsets = [
        (None, {
            'fields': ['csr', 'ca', 'profile', 'subject', 'subjectAltName', 'algorithm',
                       'expires', 'watchers', ],
        }),
        (_('X509 Extensions'), {
            'fields': ['keyUsage', 'extendedKeyUsage', ]
        }),
    ]

    def get_actions(self, request):
        # Disable the "delete selected" admin action
        actions = super(CertificateAdmin, self).get_actions(request)
        actions.pop('delete_selected', '')
        return actions

    def get_form(self, request, obj=None, **kwargs):
        if obj is None:
            return CreateCertificateForm
        else:
            return super(CertificateAdmin, self).get_form(request, obj=obj, **kwargs)

    def csr_details_view(self, request):
        try:
            csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, request.POST['csr'])
        except Exception as e:
            return HttpResponseBadRequest(json.dumps({
                'message': str(e),
            }), content_type='application/json')
        csr_subject = csr.get_subject()
        subject = {}
        for attr in ['C', 'ST', 'L', 'O', 'OU', 'CN', 'E', ]:
            if hasattr(csr_subject, attr):
                subject[attr] = getattr(csr_subject, attr)

        return HttpResponse(json.dumps({
            'subject': subject,
        }), content_type='application/json')

    def get_urls(self):
        # Remove the delete action from the URLs
        urls = super(CertificateAdmin, self).get_urls()
        meta = self.model._meta

        # remove the delete URL
        delete_name = '%s_%s_delete' % (meta.app_label, meta.verbose_name)
        urls = [u for u in urls if u.name != delete_name]

        # add revokation URL
        revoke_name = '%s_%s_revoke' % (meta.app_label, meta.verbose_name)
        revoke_view = self.admin_site.admin_view(
            RevokeCertificateView.as_view(admin_site=self.admin_site))
        urls.insert(0, url(r'^(?P<pk>.*)/revoke/$', revoke_view, name=revoke_name))

        # add csr-details url
        csr_name = '%s_%s_csr_details' % (meta.app_label, meta.verbose_name)
        urls.insert(0, url(r'^ajax/csr-details', self.admin_site.admin_view(self.csr_details_view),
                    name=csr_name))

        return urls

    def revoke_view(self, request):
        context = dict(
            self.admin_site.each_context(request)
        )
        return TemplateResponse(request, 'django_ca/admin/revoke.html', context)

    def revoke(self, request, queryset):
        for cert in queryset:
            cert.revoke()
        write_crl()
        write_index()
    revoke.short_description = _('Revoke selected certificates')

    def get_fieldsets(self, request, obj=None):
        """Collapse the "Revocation" section unless the certificate is revoked."""
        fieldsets = super(CertificateAdmin, self).get_fieldsets(request, obj=obj)

        if obj is None:
            return self.add_fieldsets

        if obj.revoked is False:
            fieldsets[2][1]['classes'] = ['collapse', ]
        else:
            if 'collapse' in fieldsets[2][1].get('classes', []):
                fieldsets[2][1]['classes'].remove('collapse')
        return fieldsets

    def get_readonly_fields(self, request, obj=None):
        if obj is None:
            return []
        return super(CertificateAdmin, self).get_readonly_fields(request, obj=obj)

    def status(self, obj):
        if obj.revoked:
            return _('Revoked')
        if obj.expires < timezone.now():
            return _('Expired')
        else:
            return _('Valid')
    status.short_description = _('Status')

    def expires_date(self, obj):
        return obj.expires.date()
    expires_date.short_description = _('Expires')
    expires_date.admin_order_field = 'expires'

    def save_model(self, request, obj, form, change):
        if change is False:  # We're adding a new certificate
            data = form.cleaned_data

            san, cn_in_san = data['subjectAltName']

            x509 = get_cert(
                ca=data['ca'],
                csr=data['csr'],
                expires=data['expires'],
                subject=data['subject'],
                algorithm=data['algorithm'],
                subjectAltName=[e.strip() for e in san.split(',')],
                cn_in_san=cn_in_san,
                keyUsage=data['keyUsage'],
                extendedKeyUsage=data['extendedKeyUsage'],
            )

            obj.cn = x509.get_subject().CN
            obj.expires = data['expires']
            obj.pub = crypto.dump_certificate(crypto.FILETYPE_PEM, x509)
        obj.save()

    class Media:
        css = {
            'all': (
                'django_ca/admin/css/certificateadmin.css',
                'django_ca/admin/css/monospace.css',
            ),
        }
        js = (
            'django_ca/admin/js/sign.js',
        )
