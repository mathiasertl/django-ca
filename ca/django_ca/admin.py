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

import binascii
import copy
import json
import os
from datetime import datetime
from functools import partial

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.certificate_transparency import LogEntryType
from cryptography.x509.extensions import UnrecognizedExtension
from cryptography.x509.oid import ExtensionOID

from django.conf.urls import url
from django.contrib import admin
from django.core.exceptions import PermissionDenied
from django.http import Http404
from django.http import HttpResponse
from django.http import HttpResponseBadRequest
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.html import escape
from django.utils.html import mark_safe
from django.utils.translation import ugettext_lazy as _

from . import ca_settings
from .forms import CreateCertificateForm
from .forms import X509CertMixinAdminForm
from .models import Certificate
from .models import CertificateAuthority
from .models import Watcher
from .signals import post_issue_cert
from .signals import pre_issue_cert
from .utils import OID_NAME_MAPPINGS
from .views import RevokeCertificateView


@admin.register(Watcher)
class WatcherAdmin(admin.ModelAdmin):
    pass


class CertificateMixin(object):
    form = X509CertMixinAdminForm

    def get_urls(self):
        info = self.model._meta.app_label, self.model._meta.model_name
        urls = [
            url(r'^(?P<pk>\d+)/download/$', self.admin_site.admin_view(self.download_view),
                name='%s_%s_download' % info),
        ]
        urls += super(CertificateMixin, self).get_urls()
        return urls

    def download_view(self, request, pk):
        """A view that allows the user to download a certificate in PEM or DER/ASN1 format."""

        if not request.user.is_staff or not self.has_change_permission(request):
            # NOTE: is_staff is already assured by ModelAdmin, but just to be sure
            raise PermissionDenied

        # get object in question
        try:
            obj = self.model.objects.get(pk=pk)
        except self.model.DoesNotExist:
            raise Http404

        # get filetype
        filetype = request.GET.get('format', 'PEM').upper().strip()

        if filetype == 'PEM':
            data = obj.pub
        elif filetype == 'DER':
            data = obj.x509.public_bytes(encoding=Encoding.DER)
        else:
            return HttpResponseBadRequest()

        filename = '%s.%s' % (obj.serial, filetype.lower())
        response = HttpResponse(data, content_type='application/pkix-cert')
        response['Content-Disposition'] = 'attachment; filename=%s' % filename
        return response

    def has_delete_permission(self, request, obj=None):
        return False

    def get_actions(self, request):
        """Disable the "delete selected" admin action.

        Otherwise the action is present even though has_delete_permission is False, it just doesn't
        work.
        """
        actions = super(CertificateMixin, self).get_actions(request)
        actions.pop('delete_selected', '')
        return actions

    ##################################
    # Properties for x509 extensions #
    ##################################

    def output_extension(self, value):
        # shared function for formatting extension values
        if value is None:
            return '<none>'

        critical, value = value
        html = ''
        if critical is True:
            text = _('Critical')
            html = '<img src="/static/admin/img/icon-yes.svg" alt="%s"> %s' % (text, text)

        if isinstance(value, list):
            html += '<ul class="x509-extension-value">'
            for val in value:
                html += '<li>%s</li>' % escape(val)
            html += '</ul>'
        else:  # string or extension
            html += '<p>%s<p>' % escape(value)

        return mark_safe(html)

    def basicConstraints(self, obj):
        return self.output_extension(obj.basicConstraints())
    basicConstraints.short_description = 'basicConstraints'

    def authorityInfoAccess(self, obj):
        return self.output_extension(obj.authorityInfoAccess())
    authorityInfoAccess.short_description = 'authorityInfoAccess'

    def keyUsage(self, obj):
        return self.output_extension(obj.keyUsage())
    keyUsage.short_description = 'keyUsage'

    def extendedKeyUsage(self, obj):
        return self.output_extension(obj.extendedKeyUsage())
    extendedKeyUsage.short_description = 'extendedKeyUsage'

    def TLSFeature(self, obj):
        return self.output_extension(obj.TLSFeature())
    TLSFeature.short_description = _('TLS Feature')

    def subjectKeyIdentifier(self, obj):
        return self.output_extension(obj.subjectKeyIdentifier())
    subjectKeyIdentifier.short_description = _('subjectKeyIdentifier')

    def issuerAltName(self, obj):
        return self.output_extension(obj.issuerAltName())
    issuerAltName.short_description = _('issuerAltName')

    def authorityKeyIdentifier(self, obj):
        return self.output_extension(obj.authorityKeyIdentifier())
    authorityKeyIdentifier.short_description = _('authorityKeyIdentifier')

    def cRLDistributionPoints(self, obj):
        return self.output_extension(obj.crlDistributionPoints())
    cRLDistributionPoints.short_description = _('CRL Distribution Points')

    def subjectAltName(self, obj):
        return self.output_extension(obj.subjectAltName())
    subjectAltName.short_description = _('subjectAltName')

    def certificatePolicies(self, obj):
        return self.output_extension(obj.certificatePolicies())
    certificatePolicies.short_description = _('Certificate Policies')

    def signedCertificateTimestampList(self, obj):
        try:
            ext = obj.x509.extensions.get_extension_for_oid(
                ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
        except x509.ExtensionNotFound:
            return ''

        if isinstance(ext.value, UnrecognizedExtension):
            return render_to_string('django_ca/admin/unrecognizedextension.html', {
                'critical': ext.critical or True,
                'entries': ext.value,
            })

        entries = []
        for entry in ext.value:
            if entry.entry_type == LogEntryType.PRE_CERTIFICATE:
                entry_type = 'Precertificate'
            elif entry.entry_type == LogEntryType.X509_CERTIFICATE:  # pragma: no cover - unseen in the wild
                # NOTE: same pragma is also in django_ca.models.X509CertMixin.signedCertificateTimestampList
                entry_type = 'X.509 certificate'
            else:  # pragma: no cover - only the above two are part of the standard
                # NOTE: same pragma is also in django_ca.models.X509CertMixin.signedCertificateTimestampList
                entry_type = _('Unknown type')

            entries.append([
                entry_type,
                entry.version.name,
                entry.timestamp,
                binascii.hexlify(entry.log_id).decode('utf-8'),  # sha256 hash
            ])

        return render_to_string('django_ca/admin/signedCertificateTimestampList.html', {
            'critical': ext.critical or True,
            'entries': entries,
        })
    signedCertificateTimestampList.short_description = _('Signed Certificate Timestamps')

    def unknown_oid(self, oid, obj):
        ext = obj.x509.extensions.get_extension_for_oid(oid)
        return self.output_extension((ext.critical, ext.value))

    def get_oid_name(self, oid):
        return oid.dotted_string.replace('.', '_')

    def get_fieldsets(self, request, obj=None):
        fieldsets = super(CertificateMixin, self).get_fieldsets(request, obj=obj)

        if obj is None:
            return fieldsets

        fieldsets = copy.deepcopy(fieldsets)
        extensions = list(sorted(obj.extensions()))
        if extensions:
            for name, _value in sorted(obj.extensions()):
                if not hasattr(self, name):
                    critical, value = _value
                    attr_name = self.get_oid_name(value)
                    func = partial(self.unknown_oid, value)
                    if name == 'UnknownOID':
                        func.short_description = 'Unkown OID (%s)' % value.dotted_string
                    else:
                        func.short_description = name
                    setattr(self, attr_name, func)
                else:
                    attr_name = name

                if attr_name == 'subjectAltName':  # already displayed in main section
                    continue

                fieldsets[self.x509_fieldset_index][1]['fields'].append(attr_name)
        else:
            fieldsets.pop(self.x509_fieldset_index)

        return fieldsets

    def get_readonly_fields(self, request, obj=None):
        fields = super(CertificateMixin, self).get_readonly_fields(request, obj=obj)

        if obj is None:  # pragma: no cover
            # This is never True because CertificateAdmin (the only case where objects are added) doesn't call
            # the superclass in this case.
            return fields

        fields = list(fields)
        for name, value in obj.extensions():
            if not hasattr(self, name):
                fields.append(self.get_oid_name(value[1]))
            else:
                fields.append(name)
        return fields

    class Media:
        css = {
            'all': (
                'django_ca/admin/css/base.css',
            ),
        }


@admin.register(CertificateAuthority)
class CertificateAuthorityAdmin(CertificateMixin, admin.ModelAdmin):
    fieldsets = (
        (None, {
            'fields': ['name', 'enabled', 'cn', 'parent', 'hpkp_pin', ],
        }),
        (_('Details'), {
            'description': _('Information to add to newly signed certificates.'),
            'fields': ['crl_url', 'issuer_url', 'ocsp_url', 'issuer_alt_name', ],
        }),
        (_('Certificate'), {
            'fields': ['serial', 'pub', 'expires'],
            # The "as-code" class is used so CSS can only match this section (and only in an
            # existing cert).
            'classes': ('as-code', ),
        }),
        (_('X509 extensions'), {
            'fields': [],  # dynamically added by add_fieldsets
        }),
    )
    list_display = ['enabled', 'name', 'serial', ]
    list_display_links = ['enabled', 'name', ]
    search_fields = ['cn', 'name', 'serial', ]
    readonly_fields = ['serial', 'pub', 'parent', 'cn', 'expires', 'hpkp_pin', ]
    x509_fieldset_index = 3

    def has_add_permission(self, request):
        return False

    class Media:
        css = {
            'all': (
                'django_ca/admin/css/base.css',
                'django_ca/admin/css/certificateauthorityadmin.css',
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
class CertificateAdmin(CertificateMixin, admin.ModelAdmin):
    actions = ['revoke', ]
    change_form_template = 'django_ca/admin/change_form.html'
    list_display = ('cn_display', 'serial', 'status', 'expires_date')
    list_filter = (StatusListFilter, 'ca')
    readonly_fields = [
        'expires', 'csr', 'pub', 'cn', 'serial', 'revoked', 'revoked_date', 'revoked_reason',
        'distinguishedName', 'ca', 'hpkp_pin', 'subjectAltName']
    search_fields = ['cn', 'serial', ]

    fieldsets = [
        (None, {
            'fields': ['cn', 'subjectAltName', 'distinguishedName', 'serial', 'ca', 'expires',
                       'watchers', 'hpkp_pin'],
        }),
        (_('X.509 Extensions'), {
            'fields': [],
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
            'fields': ['csr', ('ca', 'password'), 'profile', 'subject', 'subjectAltName', 'algorithm',
                       'expires', 'watchers', ],
        }),
        (_('X.509 Extensions'), {
            'fields': ['keyUsage', 'extendedKeyUsage', 'tlsFeature', ]
        }),
    ]
    x509_fieldset_index = 1

    def has_add_permission(self, request):
        # Only grant add permissions if there is at least one useable CA
        for ca in CertificateAuthority.objects.filter(enabled=True):
            if os.path.exists(ca.private_key_path):
                return True
        return False

    def cn_display(self, obj):
        if obj.cn:
            return obj.cn
        return _('<none>')

    def get_form(self, request, obj=None, **kwargs):
        if obj is None:
            return CreateCertificateForm
        else:
            return super(CertificateAdmin, self).get_form(request, obj=obj, **kwargs)

    def get_changeform_initial_data(self, request):
        data = super(CertificateAdmin, self).get_changeform_initial_data(request)
        data['subject'] = ca_settings.CA_PROFILES[ca_settings.CA_DEFAULT_PROFILE].get('subject', {})
        return data

    def csr_details_view(self, request):
        """Returns details of a CSR request."""

        if not request.user.is_staff or not self.has_change_permission(request):
            # NOTE: is_staff is already assured by ModelAdmin, but just to be sure
            raise PermissionDenied

        try:
            csr = x509.load_pem_x509_csr(force_bytes(request.POST['csr']), default_backend())
        except Exception as e:
            return HttpResponseBadRequest(json.dumps({
                'message': str(e),
            }), content_type='application/json')

        subject = {OID_NAME_MAPPINGS[s.oid]: s.value for s in csr.subject}
        return HttpResponse(json.dumps({
            'subject': subject,
        }), content_type='application/json')

    def get_urls(self):
        # Remove the delete action from the URLs
        urls = super(CertificateAdmin, self).get_urls()
        meta = self.model._meta

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

    def revoke(self, request, queryset):
        for cert in queryset:
            cert.revoke()
    revoke.short_description = _('Revoke selected certificates')

    def get_fieldsets(self, request, obj=None):
        """Collapse the "Revocation" section unless the certificate is revoked."""
        fieldsets = super(CertificateAdmin, self).get_fieldsets(request, obj=obj)

        if obj is None:
            return self.add_fieldsets

        if obj.revoked is False:
            fieldsets[2][1]['classes'] = ['collapse', ]
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
        data = form.cleaned_data

        # If this is a new certificate, initialize it.
        if change is False:
            san, cn_in_san = data['subjectAltName']
            expires = datetime.combine(data['expires'], datetime.min.time())
            subjectAltName = [e.strip() for e in san.split(',') if e.strip()]

            kwargs = {
                'ca': data['ca'],
                'csr': data['csr'],
                'expires': expires,
                'subject': data['subject'],
                'algorithm': data['algorithm'],
                'subjectAltName': subjectAltName,
                'cn_in_san': cn_in_san,
                'keyUsage': data['keyUsage'],
                'extendedKeyUsage': data['extendedKeyUsage'],
                'tls_features': data['tlsFeature'],
                'password': data['password'],
            }

            pre_issue_cert.send(sender=self.model, **kwargs)

            # Note: CSR is set by model form already
            obj.x509, req = self.model.objects.sign_cert(**kwargs)
            obj.save()

            # call signals
            post_issue_cert.send(sender=self.model, cert=obj)
        else:
            obj.save()

    class Media:
        css = {
            'all': (
                'django_ca/admin/css/base.css',
                'django_ca/admin/css/certificateadmin.css',
            ),
        }
        js = (
            'django_ca/admin/js/sign.js',
        )
