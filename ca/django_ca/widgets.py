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
"""Form widgets for django-ca admin interface."""
import json
import logging
import typing
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Type, Union

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from django import forms
from django.forms import widgets
from django.utils.translation import gettext as _

from django_ca import ca_settings
from django_ca.constants import (
    EXTENDED_KEY_USAGE_NAMES,
    EXTENSION_DEFAULT_CRITICAL,
    KEY_USAGE_NAMES,
    REVOCATION_REASONS,
)
from django_ca.extensions.utils import certificate_policies_is_simple
from django_ca.utils import format_general_name

log = logging.getLogger(__name__)


ExtensionWidgetsType = Tuple[Union[Type[forms.Widget], forms.Widget], ...]


class DjangoCaWidgetMixin:
    """Widget mixin with some generic functionality.

    This class is *not* intended for MultiWidget instances.

    Classes using this mixin will have a ``django-ca-widget`` CSS class and can define further classes using
    the ``css_classes`` attribute.
    """

    css_classes: Iterable[str] = ("django-ca-widget",)

    def get_css_classes(self) -> typing.Set[str]:
        """Get set of configured CSS classes."""
        css_classes = set()
        for cls in reversed(self.__class__.__mro__):
            css_classes |= set(getattr(cls, "css_classes", set()))
        return css_classes

    def add_css_classes(self, attrs: Dict[str, str]) -> None:
        """Add CSS classes to the passed attributes."""
        css_classes = " ".join(sorted(self.get_css_classes()))

        if "class" in attrs:
            attrs["class"] += f" {css_classes}"
        else:
            attrs["class"] = css_classes

    def get_context(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Get the context."""
        # TYPEHINT NOTE: This is a mixin, not worth creating a protocol just for this
        ctx: Dict[str, Any] = super().get_context(*args, **kwargs)  # type: ignore[misc]
        self.add_css_classes(ctx["widget"]["attrs"])
        return ctx


class CheckboxInput(DjangoCaWidgetMixin, widgets.CheckboxInput):
    """CheckboxInput that uses the DjangoCaWidgetMixin."""


class MultiWidget(DjangoCaWidgetMixin, widgets.MultiWidget):  # pylint: disable=abstract-method
    """MultiWidget that uses the DjangoCaWidgetMixin."""

    css_classes = ("django-ca-multiwidget",)
    template_name = "django_ca/forms/widgets/multiwidget.html"
    labels: Tuple[Optional[str], ...] = ()
    help_texts: Tuple[Optional[str], ...] = ()

    class Media:
        css = {
            "all": ("django_ca/admin/css/multiwidget.css",),
        }

    def get_context(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Get the context."""
        # TYPEHINT NOTE: This is a mixin, not worth creating a protocol just for this
        ctx: Dict[str, Any] = super().get_context(*args, **kwargs)
        for widget, label in zip(ctx["widget"]["subwidgets"], self.labels):
            widget["label"] = label
        for widget, help_text in zip(ctx["widget"]["subwidgets"], self.help_texts):
            widget["help_text"] = help_text
        return ctx


class KeyValueWidget(forms.MultiWidget):
    """Dynamic widget for key/value pairs."""

    template_name = "django_ca/admin/key_value.html"

    def __init__(
        self, key_choices: Sequence[Tuple[str, str]], attrs: Optional[Dict[str, str]] = None
    ) -> None:
        field_widgets = [
            forms.HiddenInput(),
            forms.Select(choices=key_choices, attrs=attrs),
            forms.TextInput(attrs=attrs),
        ]
        super().__init__(field_widgets, attrs=attrs)

    def decompress(self, value: Optional[x509.Name]) -> Tuple[Optional[str], None, None]:
        if value is None:
            return None, None, None

        # TYPEHINT NOTE: attr.value may be a bytes value, but this does not really happen in practice
        encoded_name: List[Dict[str, str]] = [
            {"key": attr.oid.dotted_string, "value": attr.value} for attr in value  # type: ignore[dict-item]
        ]
        return json.dumps(encoded_name), None, None

    def get_context(self, name: str, value: Any, attrs: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        context = super().get_context(name, value, attrs)

        # Remove the name as the widgets only serve as template for new key/value rows. If they had a name,
        # the browser would submit values and get them back from Django as values for the template fields in
        # case of a form error.
        del context["widget"]["subwidgets"][1]["name"]
        del context["widget"]["subwidgets"][2]["name"]

        return context

    class Media:
        js = ("django_ca/admin/js/key_value.js",)
        css = {"all": ("django_ca/admin/css/key_value.css",)}


class SubjectWidget(KeyValueWidget):
    """Specialized version of the KeyValueWidget for a certificate subject."""

    template_name = "django_ca/admin/subject.html"

    class Media:
        css = {"all": ("django_ca/admin/css/subject.css",)}


class SelectMultiple(DjangoCaWidgetMixin, widgets.SelectMultiple):
    """SelectMultiple field that uses the DjangoCaWidgetMixin."""


class Textarea(DjangoCaWidgetMixin, widgets.Textarea):
    """Textarea field that uses the DjangoCaWidgetMixin."""


class TextInput(DjangoCaWidgetMixin, widgets.TextInput):
    """TextInput field that uses the DjangoCaWidgetMixin."""


class LabeledCheckboxInput(CheckboxInput):
    """CheckboxInput widget that adds a label and wraps everything in a <span />.

    This is necessary because widgets in MultiValueFields don't render with a label.
    """

    template_name = "django_ca/forms/widgets/labeledcheckboxinput.html"

    def __init__(self, label: str, wrapper_classes: Iterable[str] = tuple()) -> None:
        self.wrapper_classes = tuple(wrapper_classes) + ("labeled-checkbox",)
        self.label = label
        super().__init__()

    def get_context(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        ctx = super().get_context(*args, **kwargs)
        ctx["widget"]["wrapper_classes"] = " ".join(self.wrapper_classes)
        ctx["widget"]["label"] = self.label

        # Tell any wrapping widget (like a MultiWidget) that this widget displays its own label.
        ctx["widget"]["handles_label"] = True
        return ctx

    class Media:
        css = {
            "all": ("django_ca/admin/css/labeledcheckboxinput.css",),
        }


class CriticalInput(LabeledCheckboxInput):
    """Widget for setting the `critical` value of an extension."""

    css_classes = ("critical",)
    template_name = "django_ca/forms/widgets/critical.html"

    def __init__(self, **kwargs: Any) -> None:
        self.oid = kwargs.pop("oid")
        super().__init__(label=_("critical"), wrapper_classes=("critical",))

    def get_context(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        ctx = super().get_context(*args, **kwargs)
        ctx["widget"]["oid"] = self.oid.dotted_string
        return ctx


class ProfileWidget(widgets.Select):
    """Widget for profile selection.

    This widget depends on the HTML having a script element with the profile-data id present somewhere in the
    DOM tree. To achieve this, add to the context::

        def get_context(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            ctx = super().get_context(*args, **kwargs)
            ctx["profiles"] = {profile.name: profile.serialize() for profile in profiles}
            return ctx

    And then use this in HTML::

        <head>
            {{ profiles|json_script:"profile-data" }}
            ...
        </head>

    In admin pages, use the ``extrahead`` block::

        {% block extrahead %}{{ block.super }}
        {{ profiles|json_script:"profile-data" }}
        {% endblock %}

    """

    template_name = "django_ca/forms/widgets/profile.html"

    def get_context(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        ctx = super().get_context(*args, **kwargs)
        ctx["desc"] = ca_settings.CA_PROFILES[ca_settings.CA_DEFAULT_PROFILE].get(
            "description", ca_settings.CA_PROFILES[ca_settings.CA_DEFAULT_PROFILE].get("desc", "")
        )
        return ctx

    class Media:
        js = (
            "admin/js/jquery.init.js",
            "django_ca/admin/js/extensions.js",
            "django_ca/admin/js/profilewidget.js",
        )
        css = {"all": ("django_ca/admin/css/profile.css",)}


class GeneralNamesWidget(Textarea):
    """Widget for a list of :py:class:`~cg:cryptography.x509.GeneralName` instances."""

    def format_value(self, value: Optional[Union[str, Iterable[x509.GeneralName]]]) -> str:
        if isinstance(value, str):  # Received during form rendering for a bound form with errors
            return value
        if not value:
            return ""
        return "\n".join([format_general_name(name) for name in value])


class ExtensionWidget(MultiWidget):  # pylint: disable=abstract-method  # is an abstract class
    """Base class for widgets that display a :py:class:`~cg:cryptography.Extension`.

    Subclasses of this class are expected to set the `extension_widgets` attribute or implement `get_widgets`.
    """

    extension_widgets: Optional[ExtensionWidgetsType]
    oid: x509.ObjectIdentifier
    css_classes = ("extension",)

    def __init__(self, attrs: Optional[Dict[str, str]] = None, **kwargs: Any) -> None:
        sub_widgets = self.get_widgets(**kwargs) + (CriticalInput(oid=self.oid),)
        super().__init__(widgets=sub_widgets, attrs=attrs)

    def get_widgets(self, **kwargs: Any) -> ExtensionWidgetsType:
        """Get sub-widgets used by this widget."""
        if self.extension_widgets is not None:  # pragma: no branch
            return self.extension_widgets
        raise ValueError(  # pragma: no cover
            "ExtensionWidget is expected to either set widgets or implement get_widgets()."
        )


class DistributionPointWidget(ExtensionWidget):
    """Widgets for extensions that use a DistributionPoint."""

    extension_widgets = (
        GeneralNamesWidget(attrs={"class": "full-name", "rows": 3}),
        TextInput(attrs={"class": "relative-name"}),
        GeneralNamesWidget(attrs={"class": "crl-issuer", "rows": 3}),
        SelectMultiple(choices=REVOCATION_REASONS, attrs={"class": "reasons"}),
    )
    labels = (
        _("Full name"),
        _("Relative name"),
        _("CRL issuer"),
        _("Reasons"),
    )

    def decompress(
        self, value: Optional[x509.Extension[x509.CRLDistributionPoints]]
    ) -> Tuple[str, str, str, List[str], bool]:
        full_name = relative_name = crl_issuer = ""
        reasons: List[str] = []

        if value is None:
            return full_name, relative_name, crl_issuer, reasons, EXTENSION_DEFAULT_CRITICAL[self.oid]
        if len(value.value) > 1:
            log.warning(
                "Received multiple DistributionPoints, only the first can be changed in the web interface."
            )

        dpoint = value.value[0]
        if dpoint.relative_name:
            relative_name = dpoint.relative_name.rfc4514_string()
        if dpoint.reasons:
            reasons = [reason.name for reason in dpoint.reasons]

        return dpoint.full_name, relative_name, dpoint.crl_issuer, reasons, value.critical


class MultipleChoiceExtensionWidget(  # pylint: disable=abstract-method  # is an abstract class
    ExtensionWidget
):
    """Base class for widgets that can be displayed with a simple SelectMultiple widget."""

    def get_widgets(  # type: ignore[override]  # we are more specific here
        self, choices: typing.Sequence[Tuple[str, str]]
    ) -> Tuple[widgets.SelectMultiple]:
        return (widgets.SelectMultiple(choices=choices),)


class AuthorityInformationAccessWidget(ExtensionWidget):
    """Widget for a :py:class:`~cg:cryptography.x509.AuthorityInformationAccess` extension."""

    extension_widgets = (
        GeneralNamesWidget(attrs={"class": "ca-issuers", "rows": 3}),
        GeneralNamesWidget(attrs={"class": "ocsp", "rows": 3}),
    )
    help_texts = (
        _("Location(s) of the CA certificate."),
        _("Location(s) of the OCSP responder."),
    )
    labels = (
        _("CA issuers"),
        _("OCSP"),
    )
    oid = ExtensionOID.AUTHORITY_INFORMATION_ACCESS

    def decompress(
        self, value: Optional[x509.Extension[x509.AuthorityInformationAccess]]
    ) -> Tuple[List[x509.GeneralName], List[x509.GeneralName], bool]:
        if value is None:
            return [], [], EXTENSION_DEFAULT_CRITICAL[self.oid]

        ocsp = [
            ad.access_location for ad in value.value if ad.access_method == AuthorityInformationAccessOID.OCSP
        ]
        ca_issuers = [
            ad.access_location
            for ad in value.value
            if ad.access_method == AuthorityInformationAccessOID.CA_ISSUERS
        ]

        return ca_issuers, ocsp, value.critical


class CertificatePoliciesWidget(ExtensionWidget):
    """Widget for a :py:class:`~cg:cryptography.x509.CertificatePolicies` extension."""

    oid = ExtensionOID.CERTIFICATE_POLICIES
    extension_widgets = (
        forms.TextInput(),  # policy identifier
        forms.Textarea(attrs={"rows": 3}),  # practice statement
        forms.Textarea(attrs={"rows": 3}),  # explicit text
    )
    help_texts = (
        "",
        _(
            "A pointers (e.g. URLs) to a certification practice statement (CPS). Separate multiple pointers "
            "with a newline."
        ),
        _("A textual statement that can be displayed to the user"),
    )
    labels = (
        _("Policy Identifier"),
        _("Certificate Practice Statement(s)"),
        _("Explicit Text"),
    )

    def decompress(
        self, value: Optional[x509.Extension[x509.CertificatePolicies]]
    ) -> Tuple[str, str, str, bool]:
        if value is None:
            return "", "", "", EXTENSION_DEFAULT_CRITICAL[ExtensionOID.CERTIFICATE_POLICIES]

        ext_value = value.value

        # COVERAGE NOTE: ruled out by the admin interface
        if certificate_policies_is_simple(ext_value) is False:  # pragma: no cover
            raise ValueError("This widget only supports a simple certificate policy values.")

        policy_information = ext_value[0]
        practice_statement: List[str] = []
        explicit_text = ""
        for policy_qualifier in policy_information.policy_qualifiers:
            if isinstance(policy_qualifier, str):
                practice_statement.append(policy_qualifier)
            else:  # UserNotice object
                explicit_text = policy_qualifier.explicit_text

        return (
            policy_information.policy_identifier.dotted_string,
            "\n".join(practice_statement),
            explicit_text,
            value.critical,
        )


class CRLDistributionPointsWidget(DistributionPointWidget):
    """Widget for a :py:class:`~cg:cryptography.x509.CRLDistributionPoints` extension."""

    help_texts = (
        _("Location(s) where to retrieve the CRL."),
        _(
            "X.500 Relative name to retrieve the CRL. RFC 5280 does not recommend setting this field. Cannot "
            "be set together with Full name."
        ),
        _("Distinguished name of the issuer of the CRL."),
        _("Revocation reasons that are included in this CRL, leave empty for all reasons (recommended)."),
    )
    oid = ExtensionOID.CRL_DISTRIBUTION_POINTS


class ExtendedKeyUsageWidget(MultipleChoiceExtensionWidget):
    """Widget for a :py:class:`~cg:cryptography.x509.ExtendedKeyUsage` extension."""

    oid = ExtensionOID.EXTENDED_KEY_USAGE

    def decompress(self, value: Optional[x509.Extension[x509.ExtendedKeyUsage]]) -> Tuple[List[str], bool]:
        if value is None:
            return [], EXTENSION_DEFAULT_CRITICAL[self.oid]
        choices = [EXTENDED_KEY_USAGE_NAMES[usage] for usage in value.value]
        return choices, value.critical


class FreshestCRLWidget(DistributionPointWidget):
    """Widget for a :py:class:`~cg:cryptography.x509.FreshestCRL` extension."""

    oid = ExtensionOID.FRESHEST_CRL


class KeyUsageWidget(MultipleChoiceExtensionWidget):
    """Widget for a :py:class:`~cg:cryptography.x509.KeyUsage` extension."""

    oid = ExtensionOID.KEY_USAGE

    def decompress(self, value: Optional[x509.Extension[x509.KeyUsage]]) -> Tuple[List[str], bool]:
        if value is None:
            return [], EXTENSION_DEFAULT_CRITICAL[self.oid]
        choices = []

        # Cannot use a list comprehension here, because cryptography raises ValueError for some attributes
        for choice in KEY_USAGE_NAMES:
            try:
                chosen = getattr(value.value, choice)
            except ValueError:
                # cryptography raises ValueError for decipher/encipher_only if key_agreement is not set
                chosen = False

            if chosen:
                choices.append(choice)

        return choices, value.critical


class IssuerAlternativeNameWidget(ExtensionWidget):
    """Widget for a :py:class:`~cg:cryptography.x509.IssuerAlternativeName` extension."""

    extension_widgets = (GeneralNamesWidget(attrs={"rows": 3}),)
    oid = ExtensionOID.ISSUER_ALTERNATIVE_NAME

    def decompress(
        self, value: Optional[x509.Extension[x509.IssuerAlternativeName]]
    ) -> Tuple[List[x509.GeneralName], bool]:
        if value is None:
            return [], EXTENSION_DEFAULT_CRITICAL[self.oid]
        return list(value.value), value.critical


class OCSPNoCheckWidget(ExtensionWidget):
    """Widget for a :py:class:`~cg:cryptography.x509.OCSPNoCheck` extension."""

    extension_widgets = (LabeledCheckboxInput(label=_("included"), wrapper_classes=["include"]),)
    oid = ExtensionOID.OCSP_NO_CHECK

    def decompress(self, value: Optional[x509.Extension[x509.OCSPNoCheck]]) -> Tuple[bool, bool]:
        if value is None:
            return False, EXTENSION_DEFAULT_CRITICAL[self.oid]
        return True, value.critical


class SubjectAlternativeNameWidget(ExtensionWidget):
    """Widget for a :py:class:`~cg:cryptography.x509.IssuerAlternativeName` extension."""

    extension_widgets = (
        GeneralNamesWidget(attrs={"rows": 3}),
        LabeledCheckboxInput(label="Include CommonName"),
    )
    oid = ExtensionOID.SUBJECT_ALTERNATIVE_NAME

    # COVERAGE NOTE: In Django 4.1, decompress is not called if compress() returns a tuple
    #       https://github.com/django/django/commit/37602e49484a88867f40e9498f86c49c2d1c5d7c
    def decompress(
        self,
        value: Optional[
            Union[
                Tuple[List[x509.GeneralName], bool, bool],
                Tuple[x509.Extension[x509.SubjectAlternativeName], bool],
            ]
        ],
    ) -> Tuple[List[x509.GeneralName], bool, bool]:  # pragma: no cover
        if value is None:
            default_cn_in_san = ca_settings.CA_PROFILES[ca_settings.CA_DEFAULT_PROFILE]["cn_in_san"]
            return [], default_cn_in_san, EXTENSION_DEFAULT_CRITICAL[self.oid]

        if len(value) == 3:
            return value

        ext, cn_in_san = value
        if ext is None:
            return [], cn_in_san, EXTENSION_DEFAULT_CRITICAL[self.oid]

        return list(ext.value), cn_in_san, ext.critical


class TLSFeatureWidget(MultipleChoiceExtensionWidget):
    """Widget for a :py:class:`~cg:cryptography.x509.TLSFeature` extension."""

    oid = ExtensionOID.TLS_FEATURE

    def decompress(self, value: Optional[x509.Extension[x509.TLSFeature]]) -> Tuple[List[str], bool]:
        if value is None:
            return [], EXTENSION_DEFAULT_CRITICAL[self.oid]
        return [feature.name for feature in value.value], value.critical
