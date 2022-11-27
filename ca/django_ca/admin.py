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

"""ModelAdmin classes for django-ca.

.. seealso:: https://docs.djangoproject.com/en/dev/ref/contrib/admin/
"""

import copy
import functools
import logging
import sys
import typing
from datetime import date, datetime
from http import HTTPStatus

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from django.contrib import admin
from django.contrib.admin.views.main import ChangeList
from django.contrib.messages import constants as messages
from django.core.exceptions import ImproperlyConfigured, PermissionDenied
from django.core.handlers.wsgi import WSGIRequest
from django.db import models
from django.forms import ModelForm
from django.forms.widgets import MediaDefiningClass
from django.http import (
    Http404,
    HttpRequest,
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseRedirect,
    JsonResponse,
)
from django.template.loader import render_to_string
from django.template.response import TemplateResponse
from django.urls import path, reverse
from django.urls.resolvers import URLPattern
from django.utils import timezone
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from django_object_actions import DjangoObjectActions

from . import ca_settings
from .constants import EXTENSION_DEFAULT_CRITICAL, EXTENSION_KEY_OIDS, EXTENSION_KEYS, ReasonFlags
from .extensions import CERTIFICATE_EXTENSIONS, get_extension_name, serialize_extension
from .extensions.utils import extension_as_admin_html
from .forms import CreateCertificateForm, ResignCertificateForm, RevokeCertificateForm, X509CertMixinAdminForm
from .models import (
    AcmeAccount,
    AcmeAuthorization,
    AcmeCertificate,
    AcmeChallenge,
    AcmeOrder,
    Certificate,
    CertificateAuthority,
    Watcher,
)
from .profiles import profiles
from .querysets import CertificateQuerySet
from .signals import post_issue_cert
from .typehints import CRLExtensionType, X509CertMixinTypeVar
from .utils import OID_NAME_MAPPINGS, SERIAL_RE, add_colons, format_name

log = logging.getLogger(__name__)

if typing.TYPE_CHECKING:
    AcmeAccountAdminBase = admin.ModelAdmin[AcmeAccount]
    AcmeAuthorizationAdminBase = admin.ModelAdmin[AcmeAuthorization]
    AcmeCertificateAdminBase = admin.ModelAdmin[AcmeCertificate]
    AcmeChallengeAdminBase = admin.ModelAdmin[AcmeChallenge]
    AcmeOrderAdminBase = admin.ModelAdmin[AcmeOrder]
    CertificateAdminBase = admin.ModelAdmin[Certificate]
    CertificateAuthorityAdminBase = admin.ModelAdmin[CertificateAuthority]
    ModelAdminBase = admin.ModelAdmin[models.Model]
    ModelAdminGenericBase = admin.ModelAdmin[X509CertMixinTypeVar]
    QuerySet = models.QuerySet[models.Model]
    WatcherAdminBase = admin.ModelAdmin[Watcher]
    MixinBase = ModelAdminBase
    CertificateModelForm = ModelForm[Certificate]
else:
    AcmeAccountAdminBase = admin.ModelAdmin
    AcmeAuthorizationAdminBase = admin.ModelAdmin
    AcmeCertificateAdminBase = admin.ModelAdmin
    AcmeChallengeAdminBase = admin.ModelAdmin
    AcmeOrderAdminBase = admin.ModelAdmin
    CertificateAdminBase = admin.ModelAdmin
    CertificateAuthorityAdminBase = admin.ModelAdmin
    ModelAdminBase = admin.ModelAdmin
    ModelAdminGenericBase = admin.ModelAdmin
    QuerySet = models.QuerySet
    WatcherAdminBase = admin.ModelAdmin
    MixinBase = object
    CertificateModelForm = ModelForm

FieldSets = typing.List[typing.Tuple[typing.Optional[str], typing.Dict[str, typing.Any]]]
QuerySetTypeVar = typing.TypeVar("QuerySetTypeVar", bound=QuerySet)

if sys.version_info >= (3, 8):  # pragma: only py>=3.8
    from typing import OrderedDict

    OrderedDictType = OrderedDict[str, str]
else:  # pragma: only py<3.8
    from collections import OrderedDict as OrderedDictType


@admin.register(Watcher)
class WatcherAdmin(WatcherAdminBase):
    """ModelAdmin for :py:class:`~django_ca.models.Watcher`."""


class CertificateMixin(
    typing.Generic[X509CertMixinTypeVar],
    MixinBase,
    metaclass=MediaDefiningClass,
):
    """Mixin for CA/Certificate."""

    form = X509CertMixinAdminForm
    x509_fieldset_index: int

    def pub_pem(self, obj: X509CertMixinTypeVar) -> str:
        """Get the CSR in PEM form for display."""
        return obj.pub.pem

    pub_pem.short_description = _("Public key")  # type: ignore[attr-defined] # django standard

    def get_urls(self) -> typing.List[URLPattern]:
        """Overridden to add urls for download/download_bundle views."""
        info = f"{self.model._meta.app_label}_{self.model._meta.model_name}"
        urls = [
            path(
                "<int:pk>/download/", self.admin_site.admin_view(self.download_view), name=f"{info}_download"
            ),
            path(
                "<int:pk>/download_bundle/",
                self.admin_site.admin_view(self.download_bundle_view),
                name=f"{info}_download_bundle",
            ),
        ]
        urls += super().get_urls()
        return urls

    def _download_response(self, request: HttpRequest, pk: int, bundle: bool = False) -> HttpResponse:
        if not request.user.is_staff or not self.has_change_permission(request):
            # NOTE: is_staff is already assured by ModelAdmin, but just to be sure
            raise PermissionDenied

        # get object in question
        try:
            obj = self.model.objects.get(pk=pk)
        except self.model.DoesNotExist as ex:
            raise Http404 from ex

        # get filetype
        filetype = request.GET.get("format", "PEM").upper().strip()

        if filetype == "PEM":
            if bundle is True:
                data = obj.bundle_as_pem
            else:
                data = obj.pub.pem
        elif filetype == "DER":
            if bundle is True:
                return HttpResponseBadRequest(_("DER/ASN.1 certificates cannot be downloaded as a bundle."))
            data = obj.pub.der
        else:
            return HttpResponseBadRequest()

        filename = obj.get_filename(ext=filetype, bundle=bundle)
        response = HttpResponse(data, content_type="application/pkix-cert")
        response["Content-Disposition"] = f"attachment; filename={filename}"
        return response

    def distinguished_name(self, obj: X509CertMixinTypeVar) -> str:
        """The certificates distinguished name formatted as string."""
        return format_name(obj.pub.loaded.subject)

    distinguished_name.short_description = _("Distinguished Name")  # type: ignore[attr-defined]

    def download_view(self, request: HttpRequest, pk: int) -> HttpResponse:
        """A view that allows the user to download a certificate in PEM or DER/ASN1 format."""

        return self._download_response(request, pk)

    def download_bundle_view(self, request: HttpRequest, pk: int) -> HttpResponse:
        """A view that allows the user to download a certificate bundle in PEM format."""

        return self._download_response(request, pk, bundle=True)

    def has_delete_permission(self, request: HttpRequest, obj: typing.Optional[models.Model] = None) -> bool:
        # pylint: disable=missing-function-docstring,unused-argument; Django standard
        return False

    def get_actions(self, request: HttpRequest) -> OrderedDictType:
        """Disable the "delete selected" admin action.

        Otherwise the action is present even though has_delete_permission is False, it just doesn't
        work.
        """
        actions = super().get_actions(request)
        actions.pop("delete_selected", "")
        return actions

    def hpkp_pin(self, obj: X509CertMixinTypeVar) -> str:
        """Property showing the HPKP bin (only adds a short description)."""
        return obj.hpkp_pin

    hpkp_pin.short_description = _("HPKP pin")  # type: ignore[attr-defined] # django standard

    def cn_display(self, obj: X509CertMixinTypeVar) -> str:
        """Display the common name or ``<none>``."""
        if obj.cn:
            return obj.cn
        return _("<none>")

    cn_display.short_description = _("CommonName")  # type: ignore[attr-defined] # django standard

    def serial_field(self, obj: X509CertMixinTypeVar) -> str:
        """Display the serial (with colons added)."""
        return add_colons(obj.serial)

    serial_field.short_description = _("Serial")  # type: ignore[attr-defined] # django standard
    serial_field.admin_order_field = "serial"  # type: ignore[attr-defined] # django standard

    def get_search_results(
        self, request: HttpRequest, queryset: QuerySet, search_term: str
    ) -> typing.Tuple[QuerySet, bool]:
        """Overridden to strip any colons from search terms (so you can search for serials with colons)."""
        # Replace ':' from any search term that looks like a serial
        search_term = " ".join(
            [
                t.replace(":", "").upper() if SERIAL_RE.match(t.upper().strip(":")) else t
                for t in search_term.split()
            ]
        )

        return super().get_search_results(request, queryset, search_term)

    ##################################
    # Properties for x509 extensions #
    ##################################

    def output_template(self, obj: X509CertMixinTypeVar, oid: x509.ObjectIdentifier) -> str:
        """Render extension for the given object."""

        ext = obj.x509_extensions.get(oid)

        if ext is None:
            # SubjectAlternativeName is displayed unconditionally in the main section, so a certificate
            # without this extension will yield a KeyError in this case.
            return render_to_string(["django_ca/admin/extensions/missing.html"])

        return extension_as_admin_html(ext)

    def __getattr__(self, name: str) -> typing.Any:
        if name.startswith("oid_"):
            oid = x509.ObjectIdentifier(name[4:].replace("_", "."))
            func = functools.partial(self.output_template, oid=oid)
            func.short_description = get_extension_name(oid)  # type: ignore[attr-defined]  # django standard
            return func
        raise AttributeError(name)

    def get_oid_name(self, oid: x509.ObjectIdentifier) -> str:
        """Get a normalized name for the given OID."""
        return f"oid_{oid.dotted_string.replace('.', '_')}"

    # TYPE NOTE: django-stubs typehints obj as Optional[Model], but we can be more specific here
    def get_fieldsets(  # type: ignore[override] # pylint: disable=missing-function-docstring
        self, request: HttpRequest, obj: typing.Optional[X509CertMixinTypeVar] = None
    ) -> FieldSets:
        fieldsets = super().get_fieldsets(request, obj=obj)

        if obj is None:
            return fieldsets

        fieldsets = copy.deepcopy(fieldsets)
        for ext in obj.sorted_extensions:
            field = self.get_oid_name(ext.oid)
            fieldsets[self.x509_fieldset_index][1]["fields"].append(field)
        return fieldsets

    def get_readonly_fields(  # type: ignore[override] # pylint: disable=missing-function-docstring
        self, request: HttpRequest, obj: typing.Optional[X509CertMixinTypeVar] = None
    ) -> typing.Union[typing.List[str], typing.Tuple[typing.Any, ...]]:
        fields = super().get_readonly_fields(request, obj=obj)

        if obj is None:  # pragma: no cover
            # This is never True because CertificateAdmin (the only case where objects are added) doesn't call
            # the superclass in this case.
            return fields

        if isinstance(fields, tuple):  # pragma: no cover # just to make mypy happy, we always use lists
            fields = list(fields)

        if not obj.revoked:
            # We can only change the date when the certificate was compromised if it's actually revoked.
            fields.append("compromised")

        extension_fields = [self.get_oid_name(oid) for oid in obj.x509_extensions]
        return list(fields) + extension_fields

    class Media:  # pylint: disable=missing-class-docstring
        css = {
            "all": ("django_ca/admin/css/base.css",),
        }


@admin.register(CertificateAuthority)
class CertificateAuthorityAdmin(CertificateMixin[CertificateAuthority], CertificateAuthorityAdminBase):
    """ModelAdmin for :py:class:`~django_ca.models.CertificateAuthority`."""

    fieldsets = [
        (
            None,
            {
                "fields": [
                    "name",
                    "enabled",
                    "cn_display",
                    "parent",
                    "hpkp_pin",
                    "caa_identity",
                    "website",
                    "terms_of_service",
                ],
            },
        ),
        (
            _("Details"),
            {
                "description": _("Information to add to newly signed certificates."),
                "fields": [
                    "crl_url",
                    "crl_number",
                    "issuer_url",
                    "ocsp_url",
                    "issuer_alt_name",
                ],
            },
        ),
        (
            _("Certificate"),
            {
                "fields": ["serial_field", "pub_pem", "expires"],
                # The "as-code" class is used so CSS can only match this section (and only in an
                # existing cert).
                "classes": ("as-code",),
            },
        ),
        (
            _("X509 extensions"),
            {
                "fields": [],  # dynamically added by add_fieldsets
            },
        ),
    ]
    list_display = [
        "enabled",
        "name",
        "serial_field",
    ]
    list_display_links = [
        "enabled",
        "name",
    ]
    search_fields = [
        "cn",
        "name",
        "serial_field",
    ]
    readonly_fields = [
        "serial_field",
        "pub_pem",
        "parent",
        "cn_display",
        "expires",
        "hpkp_pin",
    ]
    x509_fieldset_index = 3

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    # TYPE NOTE: django-stubs typehints obj as Optional[Model], but we can be more specific here
    def get_fieldsets(  # type: ignore[override]
        self, request: HttpRequest, obj: typing.Optional[CertificateAuthority] = None
    ) -> FieldSets:
        """Collapse the "Revocation" section unless the certificate is revoked."""
        fieldsets = super().get_fieldsets(request, obj=obj)
        if ca_settings.CA_ENABLE_ACME:
            fieldsets = list(copy.deepcopy(fieldsets))
            fieldsets.insert(
                1,
                (
                    _("ACME"),
                    {
                        "fields": [
                            "acme_enabled",
                            "acme_requires_contact",
                        ],
                    },
                ),
            )

        return fieldsets

    class Media:
        css = {
            "all": (
                "django_ca/admin/css/base.css",
                "django_ca/admin/css/certificateauthorityadmin.css",
            ),
        }


class DefaultListFilter(admin.SimpleListFilter):  # pylint: disable=abstract-method; lookup is not overwritten
    """Baseclass filter that lets you set the default filter.

    Inspired by https://stackoverflow.com/a/16556771.
    """

    def choices(self, changelist: ChangeList) -> typing.Iterator[typing.Dict[str, typing.Any]]:
        for lookup, title in self.lookup_choices:
            yield {
                "selected": self.value() == lookup,
                "query_string": changelist.get_query_string(
                    {
                        self.parameter_name: lookup,
                    },
                    [],
                ),
                "display": title,
            }


class StatusListFilter(DefaultListFilter):
    """Filter for status."""

    title = _("Status")
    parameter_name = "status"

    # TODO: We should check if we can use "" for the first lookup for more type safety
    def lookups(
        self, request: HttpRequest, model_admin: ModelAdminBase
    ) -> typing.List[typing.Tuple[typing.Optional[str], str]]:
        return [
            (None, _("Valid")),
            ("expired", _("Expired")),
            ("revoked", _("Revoked")),
            ("all", _("All")),
        ]

    # TYPE NOTE: django-stubs defines queryset as QuerySet[Any], but we can be more specific here
    def queryset(  # type: ignore[override]
        self, request: HttpRequest, queryset: CertificateQuerySet
    ) -> CertificateQuerySet:
        if self.value() is None:
            return queryset.valid()
        if self.value() == "expired":
            return queryset.expired()
        if self.value() == "revoked":
            return queryset.revoked()
        return queryset


class AutoGeneratedFilter(DefaultListFilter):
    """Filter for certificates that were automatically generated."""

    title = _("autogeneration")
    parameter_name = "auto"

    # TODO: We should check if we can use "" for the first lookup for more type safety
    def lookups(
        self, request: HttpRequest, model_admin: ModelAdminBase
    ) -> typing.List[typing.Tuple[typing.Optional[str], str]]:
        return [
            (None, _("No")),
            ("auto", _("Yes")),
            ("all", _("All")),
        ]

    # TYPE NOTE: django-stubs defines queryset as QuerySet[Any], but we can be more specific here
    def queryset(  # type: ignore[override]
        self, request: HttpRequest, queryset: CertificateQuerySet
    ) -> CertificateQuerySet:
        if self.value() == "auto":
            return Certificate.objects.filter(autogenerated=True)
        if self.value() is None:
            return Certificate.objects.filter(autogenerated=False)
        return queryset


@admin.register(Certificate)
class CertificateAdmin(DjangoObjectActions, CertificateMixin[Certificate], CertificateAdminBase):
    """ModelAdmin for :py:class:`~django_ca.models.Certificate`."""

    actions = [
        "revoke",
    ]
    change_actions = (
        "revoke_change",
        "resign",
    )
    add_form_template = "admin/django_ca/certificate/add_form.html"
    change_form_template = "admin/django_ca/certificate/change_form.html"
    list_display = ("cn_display", "profile", "serial_field", "status", "expires_date")
    list_filter = ("profile", AutoGeneratedFilter, StatusListFilter, "ca")
    readonly_fields = [
        "expires",
        "csr_pem",
        "pub_pem",
        "cn_display",
        "serial_field",
        "revoked",
        "revoked_date",
        "revoked_reason",
        "distinguished_name",
        "ca",
        "hpkp_pin",
        "profile",
        "oid_2_5_29_17",  # SubjectAlternativeName
    ]
    search_fields = [
        "cn",
        "serial",
    ]

    fieldsets = [
        (
            None,
            {
                "fields": [
                    "cn_display",
                    "oid_2_5_29_17",  # SubjectAlternativeName
                    "distinguished_name",
                    "serial_field",
                    "ca",
                    ("expires", "autogenerated"),
                    "watchers",
                    "hpkp_pin",
                    "profile",
                ],
            },
        ),
        (
            _("X.509 Extensions"),
            {
                "fields": [],
                "classes": ("collapse",),
            },
        ),
        (
            _("Revocation"),
            {
                "fields": (
                    ("revoked", "revoked_reason"),
                    (
                        "revoked_date",
                        "compromised",
                    ),
                ),
            },
        ),
        (
            _("Certificate"),
            {
                "fields": [
                    "pub_pem",
                    "csr_pem",
                ],
                # The "as-code" class is used so CSS can only match this section (and only in an
                # existing cert).
                "classes": ("collapse", "as-code"),
            },
        ),
    ]
    add_fieldsets: FieldSets = [
        (
            None,
            {
                "fields": [
                    "csr",
                    ("ca", "password"),
                    "profile",
                    "subject",
                    "subject_alternative_name",
                    "algorithm",
                    ("expires", "autogenerated"),
                    "watchers",
                ],
            },
        ),
        (
            _("X.509 Extensions"),
            {
                "fields": CERTIFICATE_EXTENSIONS,
                "classes": (
                    "collapse",
                    "x509-extensions",
                ),
            },
        ),
    ]

    # same as add_fieldsets but without the csr
    resign_fieldsets: FieldSets = [
        (
            None,
            {
                "fields": [
                    ("ca", "password"),
                    "profile",
                    "subject",
                    "subject_alternative_name",
                    "algorithm",
                    "expires",
                    "watchers",
                ],
            },
        ),
        (
            _("X.509 Extensions"),
            {"fields": CERTIFICATE_EXTENSIONS},
        ),
    ]
    x509_fieldset_index = 1

    @property
    def ca_details_view_name(self) -> str:
        """URL for the profiles view."""
        return f"{self.model._meta.app_label}_{self.model._meta.verbose_name}_ca_details"

    def ca_details_view(self, request: HttpRequest) -> JsonResponse:
        """View for getting the extension values from the certificate authority."""
        data: typing.Dict[int, typing.Dict[str, typing.Any]] = {}
        for ca in CertificateAuthority.objects.usable():
            if ca.key_exists is False:
                continue

            extensions = {
                EXTENSION_KEYS[oid]: serialize_extension(ext)
                for oid, ext in ca.extensions_for_certificate.items()
            }

            data[ca.pk] = {"extensions": extensions, "name": ca.name}

        return JsonResponse(data)

    def has_add_permission(self, request: HttpRequest) -> bool:
        # Only grant add permissions if there is at least one useable CA
        for ca in CertificateAuthority.objects.usable():
            if ca.key_exists:
                return True
        return False

    def csr_pem(self, obj: Certificate) -> str:
        """Get the CSR in PEM form for display."""
        return obj.csr.pem

    csr_pem.short_description = _("CSR")  # type: ignore[attr-defined] # django standard

    # TYPE NOTE: django-stubs typehints obj as Optional[Model], but we can be more specific here
    # PYLINT NOTE: pylint does not recognize that function is overwritten due to generics.
    #              https://github.com/PyCQA/pylint/issues/3605
    def get_form(  # type: ignore[override] # pylint: disable=unused-argument
        self,
        request: HttpRequest,
        obj: typing.Optional[Certificate] = None,
        change: bool = False,
        **kwargs: typing.Any,
    ) -> typing.Type[CertificateModelForm]:
        """Override to get specialized forms for signing/resigning certs."""
        if hasattr(request, "_resign_obj"):
            return ResignCertificateForm
        if obj is None:
            return CreateCertificateForm

        # TYPE NOTE: django-stubs does not seem to add typehints for this function
        return typing.cast(typing.Type[CertificateModelForm], super().get_form(request, obj=obj, **kwargs))

    def get_changeform_initial_data(self, request: HttpRequest) -> typing.Dict[str, typing.Any]:
        """Get initial data based on default profile.

        When resigning a certificate, get initial data from the certificate."""
        data: typing.Dict[str, typing.Any] = super().get_changeform_initial_data(request)

        if hasattr(request, "_resign_obj"):
            # resign the cert, so we add initial data from the original cert

            resign_obj = getattr(request, "_resign_obj")
            san = resign_obj.x509_extensions.get(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            if san is None:
                san_value = []
                san_critical = EXTENSION_DEFAULT_CRITICAL[ExtensionOID.SUBJECT_ALTERNATIVE_NAME]
            else:
                san_value = list(san.value)
                san_critical = san.critical

            # Since Django 4.1, tuples are no longer passed to a MultiWidgets decompress() method.  We must
            # thus pass a three-tuple as initial value, each corresponding to the value of one of the widgets.
            subject_alternative_name = (san_value, False, san_critical)

            algo = resign_obj.algorithm.__class__.__name__

            if resign_obj.profile:
                profile = resign_obj.profile
            else:
                profile = ca_settings.CA_DEFAULT_PROFILE

            data = {
                "algorithm": algo,
                "ca": resign_obj.ca,
                "profile": profile,
                "subject": resign_obj.subject,
                "subject_alternative_name": subject_alternative_name,
                "watchers": resign_obj.watchers.all(),
            }

            # Add values from editable extensions
            extensions = resign_obj.x509_extensions
            for key in CERTIFICATE_EXTENSIONS:
                data[key] = extensions.get(EXTENSION_KEY_OIDS[key])
        else:
            # Form for a completely new certificate

            ca = None
            try:
                ca = CertificateAuthority.objects.default()
            except ImproperlyConfigured as ex:
                log.error(ex)

            # If the default CA is not usable, use the first one that we can use instead.
            if ca is None or ca.key_exists is False:
                for usable_ca in CertificateAuthority.objects.usable().order_by("-expires", "serial"):
                    if usable_ca.key_exists:
                        ca = usable_ca

            # NOTE: This should not happen because if no CA is usable from the admin interface, the "add"
            # button would not even show up.
            if ca is None:  # pragma: no cover
                raise ImproperlyConfigured("Cannot determine default CA.")

            profile = profiles[ca_settings.CA_DEFAULT_PROFILE]
            data["ca"] = ca
            data["subject"] = profile.subject

            data.update({EXTENSION_KEYS[oid]: ext for oid, ext in ca.extensions_for_certificate.items()})

            for key in CERTIFICATE_EXTENSIONS:
                ext = profile.extensions.get(EXTENSION_KEY_OIDS[key])
                if ext is not None:
                    data[key] = ext

        return data

    def add_view(
        self,
        request: HttpRequest,
        form_url: str = "",
        extra_context: typing.Optional[typing.Dict[str, typing.Any]] = None,
    ) -> HttpResponse:
        extra_context = extra_context or {}
        extra_context["profiles_url"] = reverse(f"admin:{self.profiles_view_name}")
        extra_context["csr_details_url"] = reverse(f"admin:{self.csr_details_view_name}")
        extra_context["ca_details_url"] = reverse(f"admin:{self.ca_details_view_name}")
        return super().add_view(
            request,
            form_url=form_url,
            extra_context=extra_context,  # type: ignore[arg-type] # django-stubs wrongly thinks it's None
        )

    @property
    def csr_details_view_name(self) -> str:
        """URL for the CSR details view."""
        return f"{self.model._meta.app_label}_{self.model._meta.verbose_name}_csr_details"

    def csr_details_view(self, request: HttpRequest) -> JsonResponse:
        """Returns details of a CSR request."""

        if not request.user.is_staff or not self.has_change_permission(request):
            # NOTE: is_staff is already assured by ModelAdmin, but just to be sure
            raise PermissionDenied

        try:
            csr = x509.load_pem_x509_csr(request.POST["csr"].encode("ascii"))
        except Exception as e:  # pylint: disable=broad-except; docs don't list possible exceptions
            return JsonResponse({"message": str(e)}, status=HTTPStatus.BAD_REQUEST)

        # TODO: support CSRs with multiple OIDs (from django_ca.utils.MULTIPLE_OIDS)
        subject = {OID_NAME_MAPPINGS[s.oid]: s.value for s in csr.subject}
        return JsonResponse({"subject": subject})

    @property
    def profiles_view_name(self) -> str:
        """URL for the profiles view."""
        return f"{self.model._meta.app_label}_{self.model._meta.verbose_name}_profiles"

    def profiles_view(self, request: HttpRequest) -> JsonResponse:
        """Returns profiles."""

        if not self.has_change_permission(request):
            # NOTE: is_staff/is_active is checked by self.admin_site.admin_view()
            raise PermissionDenied

        data = {name: profiles[name].serialize() for name in ca_settings.CA_PROFILES}
        return JsonResponse(data)

    def get_urls(self) -> typing.List[URLPattern]:
        # Remove the delete action from the URLs
        urls = super().get_urls()

        # add csr-details and profiles
        urls.insert(
            0,
            path(
                "ajax/csr-details",
                self.admin_site.admin_view(self.csr_details_view),
                name=self.csr_details_view_name,
            ),
        )
        urls.insert(
            0,
            path(
                "ajax/profiles", self.admin_site.admin_view(self.profiles_view), name=self.profiles_view_name
            ),
        )
        urls.insert(
            0,
            path(
                "ajax/ca-details/",
                self.admin_site.admin_view(self.ca_details_view),
                name=self.ca_details_view_name,
            ),
        )

        return urls

    def resign(self, request: HttpRequest, obj: Certificate) -> HttpResponse:
        """View for resigning an existing certificate."""

        if not self.has_view_permission(request, obj) or not self.has_add_permission(request):
            # NOTE: is_staff/is_active is checked by self.admin_site.admin_view()
            raise PermissionDenied

        if not obj.csr:
            self.message_user(
                request, _("Certificate has no CSR (most likely because it was imported)."), messages.ERROR
            )
            return HttpResponseRedirect(obj.admin_change_url)

        # TYPE/PYLINT NOTE: _resign_obj is used by django-ca
        request._resign_obj = obj  # type: ignore[attr-defined] # pylint: disable=protected-access
        context = {
            "title": _("Resign %s for %s") % (obj._meta.verbose_name, obj),
            "original_obj": obj,
            "object_action": _("Resign"),
        }

        # TYPE NOTE: django-stubs wrongly thinks that extra_context should be Dict[str, bool]
        return self.changeform_view(request, extra_context=context)  # type: ignore[arg-type,no-any-return]

    resign.short_description = _("Resign this certificate.")  # type: ignore[attr-defined] # django standard

    def revoke_change(self, request: WSGIRequest, obj: Certificate) -> HttpResponse:
        """View for the revoke action."""
        if not self.has_change_permission(request, obj):
            # NOTE: is_staff/is_active is checked by self.admin_site.admin_view()
            raise PermissionDenied

        if obj.revoked:
            self.message_user(request, _("Certificate is already revoked."), level=messages.ERROR)
            return HttpResponseRedirect(obj.admin_change_url)

        if request.method == "POST":
            form = RevokeCertificateForm(request.POST, instance=obj)
            if form.is_valid():
                reason = form.cleaned_data["revoked_reason"]
                if reason:
                    reason = ReasonFlags[reason]
                else:
                    reason = ReasonFlags.unspecified
                obj.revoke(reason=reason, compromised=form.cleaned_data["compromised"] or None)
                return HttpResponseRedirect(obj.admin_change_url)
        else:
            form = RevokeCertificateForm(instance=obj)

        context = dict(self.admin_site.each_context(request), form=form, object=obj, opts=obj._meta)
        return TemplateResponse(request, "admin/django_ca/certificate/revoke_form.html", context)

    revoke_change.label = _("Revoke")  # type: ignore[attr-defined] # django standard
    revoke_change.short_description = _("Revoke this certificate")  # type: ignore[attr-defined]

    def revoke(self, request: HttpRequest, queryset: CertificateQuerySet) -> None:
        """Implement the revoke() action."""
        for cert in queryset:
            cert.revoke()

    revoke.short_description = _("Revoke selected certificates")  # type: ignore[attr-defined]
    revoke.allowed_permissions = ("change",)  # type: ignore[attr-defined] # django standard

    def get_change_actions(self, request: HttpRequest, object_id: int, form_url: str) -> typing.List[str]:
        actions = list(super().get_change_actions(request, object_id, form_url))
        try:
            obj = self.model.objects.get(pk=object_id)
        except self.model.DoesNotExist:
            return []

        if obj.revoked:
            actions.remove("revoke_change")
        return actions

    # TYPE NOTE: django-stubs typehints obj as Optional[Model], but we can be more specific here
    def get_fieldsets(  # type: ignore[override]
        self, request: HttpRequest, obj: typing.Optional[Certificate] = None
    ) -> FieldSets:
        """Collapse the "Revocation" section unless the certificate is revoked."""
        fieldsets = super().get_fieldsets(request, obj=obj)

        san_field_name = "oid_2_5_29_17"
        if san_field_name in fieldsets[self.x509_fieldset_index][1]["fields"]:
            fieldsets[self.x509_fieldset_index][1]["fields"].remove("oid_2_5_29_17")

        if hasattr(request, "_resign_obj"):
            fieldsets = copy.deepcopy(self.resign_fieldsets)
            fieldsets[1][1]["description"] = render_to_string(["django_ca/admin/extensions-help.html"])
            return fieldsets
        if obj is None:
            fieldsets = copy.deepcopy(self.add_fieldsets)
            fieldsets[1][1]["description"] = render_to_string(["django_ca/admin/extensions-help.html"])
            return fieldsets

        if obj.revoked is False:
            fieldsets[2][1]["classes"] = [
                "collapse",
            ]
        return fieldsets

    def get_readonly_fields(  # type: ignore[override]
        self, request: HttpRequest, obj: typing.Optional[Certificate] = None
    ) -> typing.Union[typing.List[str], typing.Tuple[typing.Any, ...]]:
        if obj is None:
            return []
        return super().get_readonly_fields(request, obj=obj)

    def status(self, obj: Certificate) -> str:
        """Get a string for the status of a certificate."""
        if obj.revoked:
            return _("Revoked")
        if obj.expires < timezone.now():
            return _("Expired")
        return _("Valid")

    status.short_description = _("Status")  # type: ignore[attr-defined] # django standard

    def expires_date(self, obj: Certificate) -> date:
        """Get the date (without time) when a cert expires."""
        return obj.expires.date()

    expires_date.short_description = _("Expires")  # type: ignore[attr-defined] # django standard
    expires_date.admin_order_field = "expires"  # type: ignore[attr-defined] # django standard

    # TYPE NOTE: django-stubs typehints obj as Model, but we can be more specific here
    def save_model(  # type: ignore[override]
        self,
        request: HttpRequest,
        obj: Certificate,
        form: typing.Union[ResignCertificateForm, CreateCertificateForm],
        change: bool,
    ) -> None:
        data = form.cleaned_data

        # If this is a new certificate, initialize it.
        if change is False:
            profile = profiles[data["profile"]]

            if hasattr(request, "_resign_obj"):
                orig_cert: Certificate = getattr(request, "_resign_obj")
                obj.csr = csr = orig_cert.csr.loaded
            else:
                # Note: ``obj.csr`` is set by model form already
                csr = data["csr"]

            expires = datetime.combine(data["expires"], datetime.min.time())

            # Set Subject Alternative Name from form
            extensions: typing.Dict[x509.ObjectIdentifier, x509.Extension[x509.ExtensionType]] = {}
            subject_alternative_name, cn_in_san = data["subject_alternative_name"]
            if subject_alternative_name:
                extensions[ExtensionOID.SUBJECT_ALTERNATIVE_NAME] = subject_alternative_name

            # Update extensions handled through the form
            for key in CERTIFICATE_EXTENSIONS:
                if data[key] is not None:
                    extensions[EXTENSION_KEY_OIDS[key]] = data[key]

            # Update extensions from the profile that cannot (yet) be changed in the web interface
            for oid, ext in profile.extensions.items():
                # If the extension is set to None by the profile, we do not add or modify it
                # (A none value means that the extension is unset if the profile is selected by the user)
                if ext is None:
                    continue

                # We currently only support the first distribution point, append others from profile
                if (
                    oid in (ExtensionOID.CRL_DISTRIBUTION_POINTS, ExtensionOID.FRESHEST_CRL)
                    and oid in extensions
                ):
                    profile_ext = typing.cast(
                        typing.Union[x509.CRLDistributionPoints, x509.FreshestCRL], ext.value
                    )
                    if len(profile_ext) > 1:  # pragma: no branch  # false positive
                        form_ext = typing.cast(x509.Extension[CRLExtensionType], extensions[oid])
                        dpoints = form_ext.value.__class__(list(form_ext.value) + profile_ext[1:])
                        extensions[oid] = x509.Extension(
                            oid=form_ext.oid, critical=form_ext.critical, value=dpoints
                        )
                    continue

                if EXTENSION_KEYS[oid] in CERTIFICATE_EXTENSIONS:  # already handled in form
                    continue
                if oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:  # already handled above
                    continue
                if oid == ExtensionOID.BASIC_CONSTRAINTS:  # set by default in profile, so ignore it
                    continue

                # Add any extension from the profile currently not changable in the web interface
                extensions[oid] = ext

            ca: CertificateAuthority = data["ca"]

            obj.profile = profile.name
            obj.update_certificate(
                ca.sign(
                    csr,
                    subject=data["subject"],
                    algorithm=data["algorithm"],
                    expires=expires,
                    extensions=extensions.values(),
                    cn_in_san=cn_in_san,
                    password=data["password"],
                )
            )
            obj.save()
            post_issue_cert.send(sender=self.model, cert=obj)
        else:
            obj.save()

    class Media:
        css = {
            "all": (
                "django_ca/admin/css/base.css",
                "django_ca/admin/css/certificateadmin.css",
            ),
        }
        js = (
            "admin/js/jquery.init.js",
            "django_ca/admin/js/sign.js",
        )


if ca_settings.CA_ENABLE_ACME:  # pragma: no branch

    class ExpiredListFilter(DefaultListFilter):
        """Filter for expired ACME orders."""

        title = _("Expired")
        parameter_name = "expired"

        def lookups(
            self, request: HttpRequest, model_admin: ModelAdminBase
        ) -> typing.List[typing.Tuple[str, str]]:
            return [
                ("0", _("No")),
                ("1", _("Yes")),
            ]

        def queryset(self, request: HttpRequest, queryset: QuerySetTypeVar) -> QuerySetTypeVar:
            now = timezone.now()

            if self.value() == "0":
                return queryset.filter(expires__gt=now)
            if self.value() == "1":
                return queryset.filter(expires__lt=now)
            return queryset

    @admin.register(AcmeAccount)
    class AcmeAccountAdmin(AcmeAccountAdminBase):
        """ModelAdmin class for :py:class:`~django_ca.models.AcmeAccount`."""

        list_display = ("first_contact", "ca", "slug", "status", "created", "terms_of_service_agreed")
        list_filter = ("ca", "status", "terms_of_service_agreed")
        readonly_fields = (
            "pem",
            "created",
        )
        search_fields = ("contact",)

        def first_contact(self, obj: AcmeAccount) -> str:
            """return the first contact address."""
            return str(obj)

        first_contact.short_description = _("Contact")  # type: ignore[attr-defined] # django standard
        first_contact.admin_order_field = "contact"  # type: ignore[attr-defined] # django standard

    @admin.register(AcmeOrder)
    class AcmeOrderAdmin(AcmeOrderAdminBase):
        """ModelAdmin class for :py:class:`~django_ca.models.AcmeOrder`."""

        list_display = (
            "slug",
            "ca",
            "status",
            "account_link",
            "expires",
        )
        list_filter = ("status", ExpiredListFilter)
        list_select_related = ("account",)
        search_fields = ("account__contact", "slug")

        def ca(self, obj: AcmeOrder) -> str:
            """Property to get a link to the CA."""
            return format_html('<a href="{}">{}</a>', obj.account.ca.admin_change_url, obj.account.ca)

        ca.short_description = _("CA")  # type: ignore[attr-defined] # django standard
        ca.admin_order_field = "account__ca"  # type: ignore[attr-defined] # django standard

        def account_link(self, obj: AcmeOrder) -> str:
            """Property to get a link to the ACME account."""
            return format_html('<a href="{}">{}</a>', obj.account.admin_change_url, obj.account)

        account_link.short_description = _("Account")  # type: ignore[attr-defined] # django standard
        account_link.admin_order_field = "account__contact"  # type: ignore[attr-defined] # django standard

    @admin.register(AcmeAuthorization)
    class AcmeAuthorizationAdmin(AcmeAuthorizationAdminBase):
        """ModelAdmin class for :py:class:`~django_ca.models.AcmeAuthorization`."""

        list_display = ("slug", "value", "status", "ca", "account", "order_display")
        list_filter = (
            "status",
            "order__account__ca",
        )
        list_select_related = ("order__account__ca",)
        search_fields = (
            "value",
            "slug",
            "order__account__contact",
        )

        def account(self, obj: AcmeAuthorization) -> str:
            """Property to get a link to the ACME account."""
            return format_html('<a href="{}">{}</a>', obj.order.account.admin_change_url, obj.order.account)

        account.short_description = _("Account")  # type: ignore[attr-defined] # django standard
        account.admin_order_field = "order__account__contact"  # type: ignore[attr-defined] # django standard

        def ca(self, obj: AcmeAuthorization) -> str:
            """Property to get a link to the CA."""
            return format_html(
                '<a href="{}">{}</a>', obj.order.account.ca.admin_change_url, obj.order.account.ca
            )

        ca.short_description = _("CA")  # type: ignore[attr-defined] # django standard
        ca.admin_order_field = "account__ca"  # type: ignore[attr-defined] # django standard

        def order_display(self, obj: AcmeAuthorization) -> str:
            """Property to get a link to the ACME order."""
            return format_html('<a href="{}">{}</a>', obj.order.admin_change_url, obj.order.slug)

        order_display.short_description = _("Order")  # type: ignore[attr-defined] # django standard
        order_display.admin_order_field = "order__slug"  # type: ignore[attr-defined] # django standard

    @admin.register(AcmeChallenge)
    class AcmeChallengeAdmin(AcmeChallengeAdminBase):
        """ModelAdmin class for :py:class:`~django_ca.models.AcmeChallenge`."""

        list_display = (
            "slug",
            "auth",
            "type",
            "status",
            "validated",
        )
        list_filter = ("type", "status", "auth__order")

    @admin.register(AcmeCertificate)
    class AcmeCertificateAdmin(AcmeCertificateAdminBase):
        """ModelAdmin class for :py:class:`~django_ca.models.AcmeCertificate`."""

        list_display = ("slug", "status", "cert", "ca", "account", "order_link")
        list_filter = (
            "order__status",
            "order__account__ca",
        )
        list_select_related = ("order__account__ca",)

        def account(self, obj: AcmeCertificate) -> str:
            """Property to get a link to the ACME account."""
            return format_html('<a href="{}">{}</a>', obj.order.account.admin_change_url, obj.order.account)

        account.short_description = _("Account")  # type: ignore[attr-defined] # django standard
        account.admin_order_field = "order__account__contact"  # type: ignore[attr-defined] # django standard

        def ca(self, obj: AcmeCertificate) -> str:
            """Property to get a link to the CA."""
            return format_html(
                '<a href="{}">{}</a>', obj.order.account.ca.admin_change_url, obj.order.account.ca
            )

        ca.short_description = _("CA")  # type: ignore[attr-defined] # django standard
        ca.admin_order_field = "order__account__ca"  # type: ignore[attr-defined] # django standard

        def order_link(self, obj: AcmeCertificate) -> str:
            """Property to get a link to the oder."""
            return format_html('<a href="{}">{}</a>', obj.order.admin_change_url, obj.order.slug)

        order_link.short_description = _("Order")  # type: ignore[attr-defined] # django standard
        order_link.admin_order_field = "order"  # type: ignore[attr-defined] # django standard

        def status(self, obj: AcmeCertificate) -> str:
            """Property to get the order status."""
            return obj.order.status

        status.short_description = _("Status")  # type: ignore[attr-defined] # django standard
        status.admin_order_field = "order__status"  # type: ignore[attr-defined] # django standard
