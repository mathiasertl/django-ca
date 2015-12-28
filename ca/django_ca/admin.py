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

from django.contrib import admin
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _

from .models import Certificate
from .models import Watcher

_x509_ext_fields = [
    'keyUsage', 'extendedKeyUsage', 'basicConstraints', 'subjectKeyIdentifier', 'issuerAltName',
    'authorityKeyIdentifier', 'crlDistributionPoints', 'authorityInfoAccess', ]


@admin.register(Watcher)
class WatcherAdmin(admin.ModelAdmin):
    pass


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
            return queryset.filter(revoked=False, expires__gt=timezone.now())
        elif self.value() == 'expired':
            return queryset.filter(revoked=False, expires__lt=timezone.now())
        elif self.value() == 'revoked':
            return queryset.filter(revoked=True)


@admin.register(Certificate)
class CertificateAdmin(admin.ModelAdmin):
    list_display = ('cn', 'serial', 'status', 'expires_date')
    list_filter = (StatusListFilter, )
    readonly_fields = ['expires', 'csr', 'pub', 'cn', 'serial', 'revoked', 'revoked_date',
                       'revoked_reason', 'subjectAltName', ] + _x509_ext_fields

    fieldsets = (
        (None, {
            'fields': ('cn', 'subjectAltName', 'serial', 'expires', 'watchers', ),
        }),
        (_('X509 Extensions'), {
            'fields': _x509_ext_fields,
            'classes': ('collapse', ),
        }),
        (_('Revocation'), {
            'fields': ('revoked', 'revoked_date', 'revoked_reason', ),
        }),
        (_('Certificate'), {
            'fields': ('pub', 'csr', ),
            'classes': ('collapse', ),
        }),
    )

    def get_fieldsets(self, request, obj=None):
        """Collapse the "Revocation" section unless the certificate is revoked."""
        fieldsets = super(CertificateAdmin, self).get_fieldsets(request, obj=obj)

        if obj is not None and obj.revoked is False:
            fieldsets[2][1]['classes'] = ('collapse', )
        return fieldsets

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

    class Media:
        css = {
            'all': ('django_ca/admin/css/certificateadmin.css', )
        }
