# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca. If not, see
# <http://www.gnu.org/licenses/>.

"""ModelAdmin classes for django-ca.

.. seealso:: https://docs.djangoproject.com/en/dev/ref/contrib/admin/
"""

import copy
import functools
import json
import logging
import typing
from datetime import date, datetime, timezone as tz
from http import HTTPStatus
from typing import Any, Dict, Iterator, List, Optional, Tuple, Type, Union

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

import django
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

from django_ca import ca_settings, constants
from django_ca.constants import EXTENSION_DEFAULT_CRITICAL, EXTENSION_KEY_OIDS, EXTENSION_KEYS, ReasonFlags
from django_ca.extensions import CERTIFICATE_EXTENSIONS, get_extension_name, serialize_extension
from django_ca.extensions.utils import certificate_policies_is_simple, extension_as_admin_html
from django_ca.forms import (
    CertificateAuthorityForm,
    CreateCertificateForm,
    ResignCertificateForm,
    RevokeCertificateForm,
    X509CertMixinAdminForm,
)
from django_ca.models import (
    AcmeAccount,
    AcmeAuthorization,
    AcmeCertificate,
    AcmeChallenge,
    AcmeOrder,
    Certificate,
    CertificateAuthority,
    Watcher,
)
from django_ca.profiles import profiles
from django_ca.querysets import CertificateQuerySet
from django_ca.signals import post_issue_cert
from django_ca.typehints import CRLExtensionType, X509CertMixinTypeVar
from django_ca.utils import SERIAL_RE, add_colons, name_for_display

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

    from django_stubs_ext import StrOrPromise, StrPromise
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

FieldSets = Union[
    List[Tuple[Optional[Union[str, "StrPromise"]], Dict[str, Any]]],
    Tuple[Tuple[Optional[Union[str, "StrPromise"]], Dict[str, Any]], ...],
]
QuerySetTypeVar = typing.TypeVar("QuerySetTypeVar", bound=QuerySet)


@admin.register(Watcher)
class WatcherAdmin(WatcherAdminBase):
    """ModelAdmin for :py:class:`~django_ca.models.Watcher`."""


class CertificateMixin(
    typing.Generic[X509CertMixinTypeVar],
    MixinBase,
    metaclass=MediaDefiningClass,
):
    """Mixin for CA/Certificate."""

    form = X509CertMixinAdminForm  # type: ignore[assignment]  # django-stubs false positive
    x509_fieldset_index: int
    model: Type[X509CertMixinTypeVar]

    def pub_pem(self, obj: X509CertMixinTypeVar) -> str:
        """Get the CSR in PEM form for display."""
        return obj.pub.pem

    pub_pem.short_description = _("Public key")  # type: ignore[attr-defined] # django standard

    def get_urls(self) -> List[URLPattern]:
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
            path(
                "ajax/profiles", self.admin_site.admin_view(self.profiles_view), name=self.profiles_view_name
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
            obj = self.model._default_manager.get(pk=pk)
        except self.model.DoesNotExist as ex:
            raise Http404 from ex

        # get filetype
        filetype = request.GET.get("format", "PEM").upper().strip()

        if filetype == "PEM":
            if bundle is True:
                data = obj.bundle_as_pem.encode("ascii")
            else:
                data = obj.pub.pem.encode("ascii")
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

    def download_view(self, request: HttpRequest, pk: int) -> HttpResponse:
        """A view that allows the user to download a certificate in PEM or DER/ASN1 format."""
        return self._download_response(request, pk)

    def download_bundle_view(self, request: HttpRequest, pk: int) -> HttpResponse:
        """A view that allows the user to download a certificate bundle in PEM format."""
        return self._download_response(request, pk, bundle=True)

    @property
    def profiles_view_name(self) -> str:
        """URL for the profiles view."""
        return f"{self.model._meta.app_label}_{self.model._meta.model_name}_profiles"

    def profiles_view(self, request: HttpRequest) -> JsonResponse:
        """Returns profiles."""
        if not self.has_change_permission(request):
            # NOTE: is_staff/is_active is checked by self.admin_site.admin_view()
            raise PermissionDenied

        data = {name: profiles[name].serialize() for name in ca_settings.CA_PROFILES}
        return JsonResponse(data)

    def has_delete_permission(self, request: HttpRequest, obj: Optional[models.Model] = None) -> bool:
        # pylint: disable=missing-function-docstring,unused-argument; Django standard
        return False

    @admin.display(description=_("Primary name"))
    def primary_name(self, obj: X509CertMixinTypeVar) -> "StrOrPromise":
        """Display the first Subject Alternative Name or the Common Name."""
        extensions = obj.x509_extensions
        if san := extensions.get(ExtensionOID.SUBJECT_ALTERNATIVE_NAME):
            # NOTE: Do not format the general name here, as this should be obvious from the list display.
            return san.value[0].value  # type: ignore[no-any-return,index]
        if obj.cn:
            return obj.cn
        # COVERAGE NOTE: Should not happen, certs have either a subject or a Subject Alternative Name
        return _("<none>")  # pragma: no cover

    @admin.display(description=_("Issuer"))
    def issuer_field(self, obj: X509CertMixinTypeVar) -> str:
        """Display the issuer as list."""
        name = name_for_display(obj.issuer)
        return render_to_string("django_ca/admin/x509_name.html", context={"name": name})

    def serial_field(self, obj: X509CertMixinTypeVar) -> str:
        """Display the serial (with colons added)."""
        return add_colons(obj.serial)

    serial_field.short_description = _("Serial")  # type: ignore[attr-defined] # django standard
    serial_field.admin_order_field = "serial"  # type: ignore[attr-defined] # django standard

    @admin.display(description=_("Subject"))
    def subject_field(self, obj: X509CertMixinTypeVar) -> str:
        """Display the subject as list."""
        name = name_for_display(obj.subject)
        return render_to_string("django_ca/admin/x509_name.html", context={"name": name})

    def get_search_results(
        self, request: HttpRequest, queryset: QuerySet, search_term: str
    ) -> Tuple[QuerySet, bool]:
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

    def __getattr__(self, name: str) -> Any:
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
        self, request: HttpRequest, obj: Optional[X509CertMixinTypeVar] = None
    ) -> FieldSets:
        fieldsets = super().get_fieldsets(request, obj=obj)

        if obj is None:
            # TYPEHINT NOTE: django-stubs uses an internal TypeVar for type hinting, making it impossible to
            # correctly typehint this function.
            return fieldsets  # type: ignore[return-value]

        fieldsets = copy.deepcopy(fieldsets)
        for ext in obj.sorted_extensions:
            field = self.get_oid_name(ext.oid)
            # TYPEHINT NOTE: django-stubs typehints as Sequence, which has no appends().
            fieldsets[self.x509_fieldset_index][1]["fields"].append(field)  # type: ignore[attr-defined]
        return fieldsets  # type: ignore[return-value]  # see other return above

    def get_readonly_fields(  # type: ignore[override] # pylint: disable=missing-function-docstring
        self, request: HttpRequest, obj: Optional[X509CertMixinTypeVar] = None
    ) -> Union[List[str], Tuple[Any, ...]]:
        fields = list(super().get_readonly_fields(request, obj=obj))

        if obj is None:  # pragma: no cover
            # This is never True because CertificateAdmin (the only case where objects are added) doesn't call
            # the superclass in this case.
            return fields

        if not obj.revoked:
            # We can only change the date when the certificate was compromised if it's actually revoked.
            fields.append("compromised")

        extension_fields = [self.get_oid_name(oid) for oid in obj.x509_extensions]
        return fields + extension_fields

    class Media:  # pylint: disable=missing-class-docstring
        css = {
            "all": ("django_ca/admin/css/base.css",),
        }


@admin.register(CertificateAuthority)
class CertificateAuthorityAdmin(CertificateMixin[CertificateAuthority], CertificateAuthorityAdminBase):
    """ModelAdmin for :py:class:`~django_ca.models.CertificateAuthority`."""

    if django.VERSION >= (5, 0):  # pragma: django>=5.0 branch
        formfield_overrides = {models.URLField: {"assume_scheme": "https"}}

    fieldsets = [
        (
            None,
            {
                "fields": [
                    "name",
                    "enabled",
                    "subject_field",
                    "serial_field",
                    "parent",
                    "issuer_field",
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
                    "sign_certificate_policies",
                ],
            },
        ),
        (
            _("OCSP responder configuration"),
            {"fields": ["ocsp_responder_key_validity", "ocsp_response_validity"]},
        ),
        (
            _("Certificate"),
            {
                "fields": ["pub_pem", "expires"],
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
    form = CertificateAuthorityForm  # type: ignore[assignment]
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
    readonly_fields = (
        "issuer_field",
        "serial_field",
        "subject_field",
        "pub_pem",
        "parent",
        "expires",
    )
    x509_fieldset_index = 4

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    # TYPE NOTE: django-stubs typehints obj as Optional[Model], but we can be more specific here
    def get_fieldsets(  # type: ignore[override]
        self, request: HttpRequest, obj: Optional[CertificateAuthority] = None
    ) -> FieldSets:
        """Collapse the "Revocation" section unless the certificate is revoked."""
        fieldsets = list(copy.deepcopy(super().get_fieldsets(request, obj=obj)))

        if obj is None:  # pragma: no cover  # we never add certificate authorities, so it's never None
            return fieldsets

        # Mark certificate policies as read-only if the configured extension is to complex for the widget.
        sign_certificate_policies = obj.sign_certificate_policies
        if sign_certificate_policies and not certificate_policies_is_simple(sign_certificate_policies.value):
            detail_fields = fieldsets[1][1]["fields"]
            sign_certificate_policies_index = detail_fields.index("sign_certificate_policies")
            detail_fields[sign_certificate_policies_index] = "sign_certificate_policies_readonly"

        api_index = 1
        if ca_settings.CA_ENABLE_ACME:
            api_index = 2
            fieldsets.insert(
                1,
                (
                    _("ACME"),
                    {
                        "fields": [
                            "acme_enabled",
                            "acme_registration",
                            "acme_profile",
                            "acme_requires_contact",
                        ],
                    },
                ),
            )

        if ca_settings.CA_ENABLE_REST_API:
            fieldsets.insert(api_index, (_("API"), {"fields": ["api_enabled"]}))

        return fieldsets

    def get_readonly_fields(  # type: ignore[override]
        self, request: HttpRequest, obj: Optional[CertificateAuthority] = None
    ) -> Union[List[str], Tuple[Any, ...]]:
        fields = tuple(super().get_readonly_fields(request, obj=obj))
        if obj is None:  # pragma: no cover  # we never add certificate authorities, so it's never None
            return fields

        sign_certificate_policies = obj.sign_certificate_policies
        if sign_certificate_policies and not certificate_policies_is_simple(sign_certificate_policies.value):
            fields = fields + ("sign_certificate_policies_readonly",)
        return fields

    def sign_certificate_policies_readonly(self, obj: CertificateAuthority) -> str:
        """Display the sign_certificate_policies_readonly as read-only field."""
        # COVERAGE NOTE: This function is only called for complex certificate policy extensions, hence it is
        # never None here.
        if obj.sign_certificate_policies is None:  # pragma: no cover
            return ""
        return extension_as_admin_html(
            obj.sign_certificate_policies,
            extra_context={
                "warning": _("This extension is to complex to be modified in the admin interface.")
            },
        )

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

    parameter_name: str

    def choices(self, changelist: ChangeList) -> Iterator[Dict[str, Any]]:
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
    def lookups(  # type: ignore[override]  # we are more specific here
        self, request: HttpRequest, model_admin: ModelAdminBase
    ) -> List[Tuple[Optional[str], "StrPromise"]]:
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
    def lookups(  # type: ignore[override]  # we are more specific here
        self, request: HttpRequest, model_admin: ModelAdminBase
    ) -> List[Tuple[Optional[str], "StrPromise"]]:
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
    list_display = ("primary_name", "profile", "serial_field", "status", "expires_date")
    list_filter = ("profile", AutoGeneratedFilter, StatusListFilter, "ca")
    readonly_fields = [
        "expires",
        "issuer_field",
        "csr_pem",
        "pub_pem",
        "serial_field",
        "subject_field",
        "revoked",
        "revoked_date",
        "revoked_reason",
        "ca",
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
                    "subject_field",
                    "oid_2_5_29_17",  # SubjectAlternativeName
                    "serial_field",
                    "ca",
                    "issuer_field",
                    ("expires", "autogenerated"),
                    "watchers",
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
        data: Dict[int, Dict[str, Any]] = {}
        for ca in CertificateAuthority.objects.usable():
            if ca.key_exists is False:
                continue

            extensions = {
                EXTENSION_KEYS[oid]: serialize_extension(ext)
                for oid, ext in ca.extensions_for_certificate.items()
            }
            hash_algorithm_name: Optional[str] = None
            if ca.algorithm is not None:
                hash_algorithm_name = constants.HASH_ALGORITHM_NAMES[type(ca.algorithm)]

            data[ca.pk] = {
                "signature_hash_algorithm": hash_algorithm_name,
                "extensions": extensions,
                "name": ca.name,
            }

        return JsonResponse(data)

    def has_add_permission(self, request: HttpRequest) -> bool:
        # Only grant add permissions if there is at least one usable CA
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
        obj: Optional[Certificate] = None,
        change: bool = False,
        **kwargs: Any,
    ) -> Type[CertificateModelForm]:
        """Override to get specialized forms for signing/resigning certs."""
        if hasattr(request, "_resign_obj"):
            return ResignCertificateForm
        if obj is None:
            return CreateCertificateForm

        # TYPE NOTE: django-stubs does not seem to add typehints for this function
        return typing.cast(Type[CertificateModelForm], super().get_form(request, obj=obj, **kwargs))

    def get_changeform_initial_data(self, request: HttpRequest) -> Dict[str, Any]:
        """Get initial data based on default profile.

        When resigning a certificate, get initial data from the certificate.
        """
        data: Dict[str, Any] = super().get_changeform_initial_data(request)

        hash_algorithm_name = ""

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

            if resign_obj.algorithm is not None:
                hash_algorithm_name = constants.HASH_ALGORITHM_NAMES[type(resign_obj.algorithm)]

            if resign_obj.profile:
                profile = resign_obj.profile
            else:
                profile = ca_settings.CA_DEFAULT_PROFILE

            data = {
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

            if ca.algorithm is not None:
                hash_algorithm_name = constants.HASH_ALGORITHM_NAMES[type(ca.algorithm)]

            data.update({EXTENSION_KEYS[oid]: ext for oid, ext in ca.extensions_for_certificate.items()})

            for key in CERTIFICATE_EXTENSIONS:
                ext = profile.extensions.get(EXTENSION_KEY_OIDS[key])
                if ext is not None:
                    data[key] = ext

        data["algorithm"] = hash_algorithm_name

        return data

    def add_view(
        self,
        request: HttpRequest,
        form_url: str = "",
        extra_context: Optional[Dict[str, Any]] = None,
    ) -> HttpResponse:
        extra_context = extra_context or {}
        extra_context["profiles_url"] = reverse(f"admin:{self.profiles_view_name}")
        extra_context["csr_details_url"] = reverse(f"admin:{self.csr_details_view_name}")
        extra_context["ca_details_url"] = reverse(f"admin:{self.ca_details_view_name}")
        extra_context["profiles"] = {profile.name: profile.serialize() for profile in profiles}

        extra_context["oid_names"] = {
            oid.dotted_string: name for oid, name in constants.NAME_OID_DISPLAY_NAMES.items()
        }

        return super().add_view(
            request,
            form_url=form_url,
            extra_context=extra_context,
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
            raw_csr = json.loads(request.body)["csr"]
            csr = x509.load_pem_x509_csr(raw_csr.encode("ascii"))
        except Exception:  # pylint: disable=broad-except; docs don't list possible exceptions
            return JsonResponse({"message": "Cannot parse CSR."}, status=HTTPStatus.BAD_REQUEST)

        subject = [{"key": s.oid.dotted_string, "value": s.value} for s in csr.subject]
        return JsonResponse({"subject": subject})

    def get_urls(self) -> List[URLPattern]:
        # Remove the delete action from the URLs
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
            "profiles": {profile.name: profile.serialize() for profile in profiles},
            "oid_names": {oid.dotted_string: name for oid, name in constants.NAME_OID_DISPLAY_NAMES.items()},
            "django_ca_action": "resign",
        }

        return self.changeform_view(request, extra_context=context)

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

    def get_change_actions(self, request: HttpRequest, object_id: int, form_url: str) -> List[str]:
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
        self, request: HttpRequest, obj: Optional[Certificate] = None
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
        self, request: HttpRequest, obj: Optional[Certificate] = None
    ) -> Union[List[str], Tuple[Any, ...]]:
        if obj is None:
            return []
        return super().get_readonly_fields(request, obj=obj)

    def status(self, obj: Certificate) -> "StrPromise":
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
        form: Union[ResignCertificateForm, CreateCertificateForm],
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

            # NOTE: Use replace() and not astimzeone(), as we want to expire at midnight in UTC time.
            #   astimezone() will assume that the naive datetime object is in the system local time and
            #   convert it to what the system would consider midnight in its local time.
            expires = datetime.combine(data["expires"], datetime.min.time()).replace(tzinfo=tz.utc)

            # Set Subject Alternative Name from form
            extensions: Dict[x509.ObjectIdentifier, x509.Extension[x509.ExtensionType]] = {}
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
                    profile_ext = typing.cast(Union[x509.CRLDistributionPoints, x509.FreshestCRL], ext.value)
                    if len(profile_ext) > 1:  # pragma: no branch  # false positive
                        form_ext = typing.cast(x509.Extension[CRLExtensionType], extensions[oid])
                        distribution_points = form_ext.value.__class__(list(form_ext.value) + profile_ext[1:])
                        extensions[oid] = x509.Extension(
                            oid=form_ext.oid, critical=form_ext.critical, value=distribution_points
                        )
                    continue

                if EXTENSION_KEYS[oid] in CERTIFICATE_EXTENSIONS:  # already handled in form
                    continue
                if oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:  # already handled above
                    continue
                if oid == ExtensionOID.BASIC_CONSTRAINTS:  # set by default in profile, so ignore it
                    continue

                # Add any extension from the profile currently not changeable in the web interface
                extensions[oid] = ext  # pragma: no cover  # all extensions should be handled above!

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

        def lookups(  # type: ignore  # we are more specific here
            self, request: HttpRequest, model_admin: ModelAdminBase
        ) -> List[Tuple[str, "StrPromise"]]:
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

        if django.VERSION >= (5, 0):  # pragma: django>=5.0 branch
            formfield_overrides = {models.URLField: {"assume_scheme": "https"}}

        list_display = ("first_contact", "ca", "slug", "status", "created", "terms_of_service_agreed")
        list_filter = ("ca", "status", "terms_of_service_agreed")
        readonly_fields = (
            "pem",
            "created",
        )
        search_fields = ("contact",)

        def first_contact(self, obj: AcmeAccount) -> str:
            """Return the first contact address."""
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
