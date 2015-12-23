from datetime import datetime

from django.contrib import admin
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _

from .models import Certificate

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
            return queryset.filter(revoked=False, expires__gt=datetime.utcnow())
        elif self.value() == 'expired':
            return queryset.filter(revoked=False, expires__lt=datetime.utcnow())
        elif self.value() == 'revoked':
            return queryset.filter(revoked=True)


@admin.register(Certificate)
class CertificateAdmin(admin.ModelAdmin):
    list_display = ('cn', 'status', 'expires_date')
    list_filter = (StatusListFilter, )
    readonly_fields = ('expires', 'csr', 'pub', 'cn', 'serial', 'revoked', 'revoked_date',
                       'revoked_reason', )

    def status(self, obj):
        if obj.revoked:
            return _('Revoked')
        if obj.expires < datetime.utcnow():
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
