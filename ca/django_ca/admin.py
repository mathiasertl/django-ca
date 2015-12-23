from django.contrib import admin

from .models import Certificate

@admin.register(Certificate)
class CertificateAdmin(admin.ModelAdmin):
    pass
