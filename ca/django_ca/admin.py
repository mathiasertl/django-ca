from datetime import datetime

from django.contrib import admin
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _

from .models import Certificate

@admin.register(Certificate)
class CertificateAdmin(admin.ModelAdmin):
    list_display = ('cn', 'status', 'expires_date')
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
