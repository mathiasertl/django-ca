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

import copy
import json
import logging
from datetime import datetime
from functools import partial
from types import MethodType

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding

from django.contrib import admin
from django.contrib.messages import constants as messages
from django.core.exceptions import PermissionDenied
from django.http import Http404
from django.http import HttpResponse
from django.http import HttpResponseBadRequest
from django.http import HttpResponseRedirect
from django.template.loader import render_to_string
from django.template.response import TemplateResponse
from django.urls import path
from django.urls import reverse
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.html import escape
from django.utils.translation import gettext_lazy as _

from django_object_actions import DjangoObjectActions

from . import ca_settings
from .constants import ReasonFlags
from .extensions import KEY_TO_EXTENSION
from .extensions import AlternativeNameExtension
from .extensions import CRLDistributionPointsBase
from .extensions import ExtendedKeyUsage
from .extensions import KeyUsage
from .extensions import NullExtension
from .extensions import OrderedSetExtension
from .extensions import SubjectAlternativeName
from .extensions import TLSFeature
from .extensions import UnrecognizedExtension
from .forms import CreateCertificateForm
from .forms import ResignCertificateForm
from .forms import RevokeCertificateForm
from .forms import X509CertMixinAdminForm
from .models import Certificate
from .models import CertificateAuthority
from .models import Watcher
from .profiles import profiles
from .signals import post_issue_cert
from .utils import OID_NAME_MAPPINGS
from .utils import SERIAL_RE
from .utils import LazyEncoder
from .utils import add_colons

log = logging.getLogger(__name__)


@admin.register(Watcher)
class WatcherAdmin(admin.ModelAdmin):
    pass


class CertificateMixin(object):
    form = X509CertMixinAdminForm

    def get_urls(self):
        info = self.model._meta.app_label, self.model._meta.model_name
        urls = [
            path('<int:pk>/download/', self.admin_site.admin_view(self.download_view),
                 name='%s_%s_download' % info),
            path('<int:pk>/download_bundle/', self.admin_site.admin_view(self.download_bundle_view),
                 name='%s_%s_download_bundle' % info),
        ]
        urls += super(CertificateMixin, self).get_urls()
        return urls

    def _download_response(self, request, pk, bundle=False):
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
            if bundle is True:
                data = '\n'.join([cert.pub.strip() for cert in obj.bundle])
            else:
                data = obj.pub
        elif filetype == 'DER':
            if bundle is True:
                return HttpResponseBadRequest(_('DER/ASN.1 certificates cannot be downloaded as a bundle.'))
            data = obj.x509.public_bytes(encoding=Encoding.DER)
        else:
            return HttpResponseBadRequest()

        filename = obj.get_filename(ext=filetype, bundle=bundle)
        response = HttpResponse(data, content_type='application/pkix-cert')
        response['Content-Disposition'] = 'attachment; filename=%s' % filename
        return response

    def download_view(self, request, pk):
        """A view that allows the user to download a certificate in PEM or DER/ASN1 format."""

        return self._download_response(request, pk)

    def download_bundle_view(self, request, pk):
        """A view that allows the user to download a certificate bundle in PEM format."""

        return self._download_response(request, pk, bundle=True)

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

    def hpkp_pin(self, obj):
        return obj.hpkp_pin
    hpkp_pin.short_description = _('HPKP pin')

    def cn_display(self, obj):
        if obj.cn:
            return obj.cn
        return _('<none>')
    cn_display.short_description = _('CommonName')

    def serial_field(self, obj):
        return add_colons(obj.serial)
    serial_field.short_description = _('Serial')
    serial_field.admin_order_field = 'serial'

    def get_search_results(self, request, queryset, search_term):
        # Replace ':' from any search term that looks like a serial
        search_term = ' '.join([
            t.replace(':', '').upper() if SERIAL_RE.match(t.upper().strip(':')) else t
            for t in search_term.split()
        ])

        return super(CertificateMixin, self).get_search_results(request, queryset, search_term)

    ##################################
    # Properties for x509 extensions #
    ##################################

    def output_template(self, obj, key):
        ext = getattr(obj, key)
        templates = ['django_ca/admin/extensions/%s.html' % key]

        if isinstance(ext, NullExtension):
            templates.append('django_ca/admin/extensions/base/null_extension.html')
        if isinstance(ext, AlternativeNameExtension):
            templates.append('django_ca/admin/extensions/base/alternative_name_extension.html')
        if isinstance(ext, CRLDistributionPointsBase):
            templates.append('django_ca/admin/extensions/base/crl_distribution_points_base.html')
        if isinstance(ext, OrderedSetExtension):
            templates.append('django_ca/admin/extensions/base/ordered_set_extension.html')
        if isinstance(ext, UnrecognizedExtension) \
                or isinstance(ext, x509.UnrecognizedExtension):  # pragma: no cover
            templates.append('django_ca/admin/extensions/base/unrecognized_extension.html')
        else:
            templates.append('django_ca/admin/extensions/base/base.html')
        return render_to_string(templates, {'obj': obj, 'extension': ext})

    def unknown_oid(self, oid, obj):
        ext = obj.x509.extensions.get_extension_for_oid(oid)
        html = ''
        if ext.critical is True:
            text = _('Critical')
            html = '<img src="/static/admin/img/icon-yes.svg" alt="%s"> %s' % (text, text)

        html += '<p>%s<p>' % escape(ext.value)
        return html

    def get_oid_name(self, oid):
        return oid.dotted_string.replace('.', '_')

    def get_fieldsets(self, request, obj=None):
        fieldsets = super(CertificateMixin, self).get_fieldsets(request, obj=obj)

        if obj is None:
            return fieldsets

        fieldsets = copy.deepcopy(fieldsets)

        if obj.extension_fields:
            for field in obj.extension_fields:
                if field == SubjectAlternativeName.key:  # already displayed in main section
                    continue

                # If we encounter an object of type x509.Extension, it means that we do not yet support this
                # extension, hence there are no accessors either. We compute a name for the extension based on
                # the OID, create a partial function of unknown_oid and attach it under that name to this
                # admin instance:
                if isinstance(field, x509.Extension):
                    func = partial(self.unknown_oid, field.oid)
                    func.short_description = 'Unkown OID (%s)' % field.oid.dotted_string

                    field = self.get_oid_name(field.oid)

                    # attach function to this instance
                    setattr(self, field, func)

                fieldsets[self.x509_fieldset_index][1]['fields'].append(field)

        else:
            # we have no extensions, so remove the whole fieldset
            fieldsets.pop(self.x509_fieldset_index)

        return fieldsets

    def get_readonly_fields(self, request, obj=None):
        fields = super(CertificateMixin, self).get_readonly_fields(request, obj=obj)

        if not obj.revoked:
            # We can only change the date when the certificate was compromised if it's actually revoked.
            fields.append('compromised')

        if obj is None:  # pragma: no cover
            # This is never True because CertificateAdmin (the only case where objects are added) doesn't call
            # the superclass in this case.
            return fields

        fields = list(fields)
        for field in obj.extension_fields:
            if isinstance(field, x509.Extension):
                field = self.get_oid_name(field.oid)

            fields.append(field)

        return fields

    class Media:
        css = {
            'all': (
                'django_ca/admin/css/base.css',
            ),
        }


# Attach extension properties to admin if they are not already present.
# This makes ModelAdmin have a property for every extension that we currently support,
# rendering as a template based on the extension key.
for key, ext in KEY_TO_EXTENSION.items():
    # Give Mixin opportunity to override method - not needed right now
    #if hasattr(CertificateMixin, key):
    #    continue

    f = partial(CertificateMixin.output_template, key=key)
    f.short_description = ext.name
    f = MethodType(f, CertificateMixin)

    setattr(CertificateMixin, key, f)


@admin.register(CertificateAuthority)
class CertificateAuthorityAdmin(CertificateMixin, admin.ModelAdmin):
    fieldsets = (
        (None, {
            'fields': ['name', 'enabled', 'cn_display', 'parent', 'hpkp_pin', ],
        }),
        (_('Details'), {
            'description': _('Information to add to newly signed certificates.'),
            'fields': ['crl_url', 'crl_number', 'issuer_url', 'ocsp_url', 'issuer_alt_name', ],
        }),
        (_('Certificate'), {
            'fields': ['serial_field', 'pub', 'expires'],
            # The "as-code" class is used so CSS can only match this section (and only in an
            # existing cert).
            'classes': ('as-code', ),
        }),
        (_('X509 extensions'), {
            'fields': [],  # dynamically added by add_fieldsets
        }),
    )
    list_display = ['enabled', 'name', 'serial_field', ]
    list_display_links = ['enabled', 'name', ]
    search_fields = ['cn', 'name', 'serial_field', ]
    readonly_fields = ['serial_field', 'pub', 'parent', 'cn_display', 'expires', 'hpkp_pin', ]
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


class DefaultListFilter(admin.SimpleListFilter):
    """Filter that lists only manually created certs by default.

    Inspired by https://stackoverflow.com/a/16556771.
    """

    def choices(self, cl):
        for lookup, title in self.lookup_choices:
            yield {
                'selected': self.value() == lookup,
                'query_string': cl.get_query_string({
                    self.parameter_name: lookup,
                }, []),
                'display': title,
            }


class StatusListFilter(DefaultListFilter):
    title = _('Status')
    parameter_name = 'status'

    def lookups(self, request, model_admin):
        return (
            (None, _('Valid')),
            ('expired', _('Expired')),
            ('revoked', _('Revoked')),
            ('all', _('All')),
        )

    def queryset(self, request, queryset):
        if self.value() is None:
            return queryset.valid()
        elif self.value() == 'expired':
            return queryset.expired()
        elif self.value() == 'revoked':
            return queryset.revoked()


class AutoGeneratedFilter(DefaultListFilter):
    title = _('autogeneration')
    parameter_name = 'auto'

    def lookups(self, request, model_admin):
        return (
            (None, _('No')),
            ('auto', _('Yes')),
            ('all', _('All')),
        )

    def queryset(self, request, queryset):
        if self.value() == 'auto':
            return Certificate.objects.filter(autogenerated=True)
        elif self.value() is None:
            return Certificate.objects.filter(autogenerated=False)
        # "all" does not need a filter


@admin.register(Certificate)
class CertificateAdmin(DjangoObjectActions, CertificateMixin, admin.ModelAdmin):
    actions = ['revoke', ]
    change_actions = ('revoke_change', 'resign', )
    add_form_template = 'admin/django_ca/certificate/add_form.html'
    change_form_template = 'admin/django_ca/certificate/change_form.html'
    list_display = ('cn_display', 'profile', 'serial_field', 'status', 'expires_date')
    list_filter = ('profile', AutoGeneratedFilter, StatusListFilter, 'ca')
    readonly_fields = [
        'expires', 'csr', 'pub', 'cn_display', 'serial_field', 'revoked', 'revoked_date', 'revoked_reason',
        'distinguishedName', 'ca', 'hpkp_pin', 'subject_alternative_name', 'profile', ]
    search_fields = ['cn', 'serial', ]

    fieldsets = [
        (None, {
            'fields': ['cn_display', 'subject_alternative_name', 'distinguishedName', 'serial_field', 'ca',
                       ('expires', 'autogenerated'), 'watchers', 'hpkp_pin', 'profile', ],
        }),
        (_('X.509 Extensions'), {
            'fields': [],
            'classes': ('collapse', ),
        }),
        (_('Revocation'), {
            'fields': (('revoked', 'revoked_reason'),
                       ('revoked_date', 'compromised', )),
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
            'fields': ['csr', ('ca', 'password'), 'profile', 'subject', 'subject_alternative_name',
                       'algorithm', ('expires', 'autogenerated'), 'watchers', ],
        }),
        (_('X.509 Extensions'), {
            'fields': ['key_usage', 'extended_key_usage', 'tls_feature', ]
        }),
    ]

    # same as add_fieldsets but without the csr
    resign_fieldsets = [
        (None, {
            'fields': [('ca', 'password'), 'profile', 'subject', 'subject_alternative_name', 'algorithm',
                       'expires', 'watchers', ],
        }),
        (_('X.509 Extensions'), {
            'fields': ['key_usage', 'extended_key_usage', 'tls_feature', ]
        }),
    ]
    x509_fieldset_index = 1

    def has_add_permission(self, request):
        # Only grant add permissions if there is at least one useable CA
        for ca in CertificateAuthority.objects.filter(enabled=True):
            if ca.key_exists:
                return True
        return False

    def get_form(self, request, obj=None, **kwargs):
        if hasattr(request, '_resign_obj'):
            return ResignCertificateForm
        elif obj is None:
            return CreateCertificateForm
        else:
            return super(CertificateAdmin, self).get_form(request, obj=obj, **kwargs)

    def get_changeform_initial_data(self, request):
        data = super(CertificateAdmin, self).get_changeform_initial_data(request)

        if hasattr(request, '_resign_obj'):
            # resign the cert, so we add initial data from the original cert

            resign_obj = getattr(request, '_resign_obj')
            san = resign_obj.subject_alternative_name
            if san is None:
                san = ('', False)
            else:
                san = (','.join(san), False)
            algo = resign_obj.algorithm.__class__.__name__

            data = {
                'algorithm': algo,
                'ca': resign_obj.ca,
                'extended_key_usage': resign_obj.extended_key_usage,
                'key_usage': resign_obj.key_usage,
                # TODO: pass profile once it's stored to the database
                #'profile': '',
                'subject': resign_obj.subject,
                'subject_alternative_name': san,
                'tls_feature': resign_obj.tls_feature,
                'watchers': resign_obj.watchers.all(),
            }
        else:
            data['subject'] = ca_settings.CA_PROFILES[ca_settings.CA_DEFAULT_PROFILE].get('subject', {})

        return data

    def add_view(self, request, form_url='', extra_context=None):
        extra_context = extra_context or {}
        extra_context['profiles_url'] = reverse('admin:%s' % self.profiles_view_name)
        extra_context['csr_details_url'] = reverse('admin:%s' % self.csr_details_view_name)
        return super(CertificateAdmin, self).add_view(request, form_url=form_url, extra_context=extra_context)

    @property
    def csr_details_view_name(self):
        return '%s_%s_csr_details' % (self.model._meta.app_label, self.model._meta.verbose_name)

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

    @property
    def profiles_view_name(self):
        return '%s_%s_profiles' % (self.model._meta.app_label, self.model._meta.verbose_name)

    def profiles_view(self, request):
        """Returns profiles."""

        if not request.user.is_staff or not self.has_change_permission(request):
            # NOTE: is_staff is already assured by ModelAdmin, but just to be sure
            raise PermissionDenied

        data = {name: profiles[name].serialize() for name in ca_settings.CA_PROFILES}
        return HttpResponse(json.dumps(data, cls=LazyEncoder), content_type='application/json')

    def get_urls(self):
        # Remove the delete action from the URLs
        urls = super(CertificateAdmin, self).get_urls()

        # add csr-details and profiles
        urls.insert(0, path('ajax/csr-details', self.admin_site.admin_view(self.csr_details_view),
                            name=self.csr_details_view_name))
        urls.insert(0, path('ajax/profiles', self.admin_site.admin_view(self.profiles_view),
                            name=self.profiles_view_name))

        return urls

    def resign(self, request, obj):
        if not obj.csr:
            self.message_user(request, _('Certificate has no CSR (most likely because it was imported).'),
                              messages.ERROR)
            return HttpResponseRedirect(obj.admin_change_url)

        request._resign_obj = obj
        extra_context = {
            'title': _('Resign %s for %s') % (obj._meta.verbose_name, obj),
            'original_obj': obj,
            'object_action': _('Resign'),
        }
        return self.changeform_view(request, extra_context=extra_context)
    resign.short_description = _('Resign this certificate.')

    def revoke_change(self, request, obj):
        if not self.has_change_permission(request, obj):
            raise PermissionDenied
        if obj.revoked:
            self.message_user(request, _('Certificate is already revoked.'), level=messages.ERROR)
            return HttpResponseRedirect(obj.admin_change_url)

        if request.method == 'POST':
            form = RevokeCertificateForm(request.POST, instance=obj)
            if form.is_valid():
                reason = form.cleaned_data['revoked_reason']
                if reason:
                    reason = ReasonFlags[reason]

                obj.revoke(
                    reason=reason,
                    compromised=form.cleaned_data['compromised'] or None
                )
                return HttpResponseRedirect(obj.admin_change_url)
        else:
            form = RevokeCertificateForm(instance=obj)

        context = dict(self.admin_site.each_context(request), form=form, object=obj, opts=obj._meta)
        return TemplateResponse(request, "admin/django_ca/certificate/revoke_form.html", context)
    revoke_change.label = _('Revoke')
    revoke_change.short_description = _('Revoke this certificate')

    def revoke(self, request, queryset):
        for cert in queryset:
            cert.revoke()
    revoke.short_description = _('Revoke selected certificates')

    def get_change_actions(self, request, object_id, form_url):
        actions = list(super(CertificateAdmin, self).get_change_actions(request, object_id, form_url))
        try:
            obj = self.model.objects.get(pk=object_id)
        except self.model.DoesNotExist:
            return []

        if obj.revoked:
            actions.remove('revoke_change')
        return actions

    def get_fieldsets(self, request, obj=None):
        """Collapse the "Revocation" section unless the certificate is revoked."""
        fieldsets = super(CertificateAdmin, self).get_fieldsets(request, obj=obj)

        if hasattr(request, '_resign_obj'):
            return self.resign_fieldsets
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
            profile = profiles[data['profile']]

            if hasattr(request, '_resign_obj'):
                csr = getattr(request, '_resign_obj').csr
                obj.csr = csr
            else:
                # Note: CSR is set by model form already
                csr = data['csr']

            parsed_csr = Certificate.objects.parse_csr(csr, Encoding.PEM)
            expires = datetime.combine(data['expires'], datetime.min.time())

            extensions = {}
            san, cn_in_san = data['subject_alternative_name']
            san = SubjectAlternativeName({'value': [e.strip() for e in san.split(',') if e.strip()]})
            if san:
                extensions[SubjectAlternativeName.key] = san
            for ext_key in [KeyUsage.key, ExtendedKeyUsage.key, TLSFeature.key]:
                if data[ext_key].value:
                    extensions[ext_key] = data[ext_key]
                else:
                    extensions[ext_key] = None

            obj.profile = profile.name
            obj.x509 = profile.create_cert(data['ca'], parsed_csr, subject=data['subject'], expires=expires,
                                           algorithm=data['algorithm'], cn_in_san=cn_in_san,
                                           password=data['password'], extensions=extensions)
            obj.save()
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
            'admin/js/jquery.init.js',
            'django_ca/admin/js/sign.js',
        )
