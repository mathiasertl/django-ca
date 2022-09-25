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

"""Form widgets for django-ca admin interface."""

import typing

from cryptography import x509

from django import forms
from django.forms import widgets
from django.utils.translation import gettext as _

from . import ca_settings
from .extensions.utils import EXTENDED_KEY_USAGE_NAMES, KEY_USAGE_NAMES
from .utils import ADMIN_SUBJECT_OIDS, format_general_name


class LabeledCheckboxInput(widgets.CheckboxInput):
    """CheckboxInput widget that adds a label and wraps everything in a <span />.

    This is necessary because widgets in MultiValueFields don't render with a label."""

    template_name = "django_ca/forms/widgets/labeledcheckboxinput.html"

    def __init__(self, label: str, wrapper_classes: typing.Iterable[str] = tuple()) -> None:
        self.wrapper_classes = tuple(wrapper_classes) + ("labeled-checkbox",)
        self.label = label
        super().__init__()

    def get_context(self, *args: typing.Any, **kwargs: typing.Any) -> typing.Dict[str, typing.Any]:
        ctx = super().get_context(*args, **kwargs)
        ctx["widget"]["wrapper_classes"] = " ".join(self.wrapper_classes)
        ctx["widget"]["label"] = self.label
        return ctx

    class Media:
        css = {
            "all": ("django_ca/admin/css/labeledcheckboxinput.css",),
        }


class CriticalInput(LabeledCheckboxInput):
    """Widget for setting the `critical` value of an extension."""

    classes = ("critical",)

    def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        super().__init__(label=_("critical"), wrapper_classes=("critical",))


class LabeledTextInput(widgets.TextInput):
    """CheckboxInput widget that adds a label and wraps everything in a <span />.

    This is necessary because widgets in MultiValueFields don't render with a label."""

    template_name = "django_ca/forms/widgets/labeledtextinput.html"

    def __init__(self, label: str, *args: typing.Any, **kwargs: typing.Any):
        self.label = label
        super().__init__(*args, **kwargs)

    def get_context(self, *args: typing.Any, **kwargs: typing.Any) -> typing.Dict[str, typing.Any]:
        ctx = super().get_context(*args, **kwargs)
        ctx["widget"]["label"] = self.label
        ctx["widget"]["cssid"] = self.label.lower().replace(" ", "-")
        return ctx

    class Media:
        css = {
            "all": ("django_ca/admin/css/labeledtextinput.css",),
        }


class SubjectTextInput(LabeledTextInput):
    """Widget used in :py:class:`~django_ca.widgets.SubjectWidget`."""

    template_name = "django_ca/forms/widgets/subjecttextinput.html"


class ProfileWidget(widgets.Select):
    """Widget for profile selection."""

    template_name = "django_ca/forms/widgets/profile.html"

    def get_context(self, *args: typing.Any, **kwargs: typing.Any) -> typing.Dict[str, typing.Any]:
        ctx = super().get_context(*args, **kwargs)
        ctx["desc"] = ca_settings.CA_PROFILES[ca_settings.CA_DEFAULT_PROFILE].get(
            "description", ca_settings.CA_PROFILES[ca_settings.CA_DEFAULT_PROFILE].get("desc", "")
        )
        return ctx

    class Media:
        js = (
            "admin/js/jquery.init.js",
            "django_ca/admin/js/profilewidget.js",
        )


class CustomMultiWidget(widgets.MultiWidget):  # pylint: disable=abstract-method; decompress() in subclasses
    """Wraps the multi widget into a <p> element (base class for other widgets)."""

    template_name = "django_ca/forms/widgets/custommultiwidget.html"


class SubjectWidget(CustomMultiWidget):
    """Widget for a :py:class:`~django_ca.subject.Subject`."""

    def __init__(self, attrs: typing.Optional[typing.Dict[str, str]] = None) -> None:
        _widgets = (
            SubjectTextInput(label=_("Country"), attrs={"placeholder": "2 character country code"}),
            SubjectTextInput(label=_("State")),
            SubjectTextInput(label=_("Location")),
            SubjectTextInput(label=_("Organization")),
            SubjectTextInput(label=_("Organizational Unit")),
            SubjectTextInput(label=_("CommonName"), attrs={"required": True}),
            SubjectTextInput(label=_("E-Mail")),
        )
        super().__init__(_widgets, attrs)

    def decompress(self, value: typing.Optional[x509.Name]) -> typing.List[str]:
        if not value:
            return ["" for attr in ADMIN_SUBJECT_OIDS]

        attr_mapping = {attr.oid: attr.value for attr in value}
        return [attr_mapping.get(oid, "") for oid in ADMIN_SUBJECT_OIDS]  # type: ignore[misc]


class SubjectAltNameWidget(CustomMultiWidget):
    """Widget for a Subject Alternative Name extension."""

    def __init__(self, attrs: typing.Optional[typing.Dict[str, str]] = None) -> None:
        _widgets = (widgets.TextInput(), LabeledCheckboxInput(label="Include CommonName"))
        super().__init__(_widgets, attrs)

    # COVERAGE NOTE: In Django 4.1, decompress is not called if compress() returns a tuple
    #       https://github.com/django/django/commit/37602e49484a88867f40e9498f86c49c2d1c5d7c
    def decompress(
        self, value: typing.Optional[typing.Tuple[str, bool]]
    ) -> typing.Tuple[str, bool]:  # pragma: no cover
        # Invoked when resigning a certificate
        if value:  # pragma: no branch
            return value

        # Since the value is at least a Tuple[str, bool], the above check is never False.
        # Keep this here just to be sure.
        return ("", True)  # pragma: no cover


class ExtensionWidget(widgets.MultiWidget):  # pylint: disable=abstract-method  # is an abstract class
    """Base class for widgets that display a :py:class:`~cg:cryptography.Extension`.

    Subclasses of this class are expected to set the `extension_widgets` attribute or implement `get_widgets`.
    """

    extension_widgets: typing.Optional[typing.Tuple[forms.Widget, ...]]
    template_name = "django_ca/forms/widgets/extension.html"

    def __init__(self, attrs: typing.Optional[typing.Dict[str, str]] = None, **kwargs: typing.Any) -> None:
        sub_widgets = self.get_widgets(**kwargs) + (CriticalInput(),)
        super().__init__(widgets=sub_widgets, attrs=attrs)

    def get_widgets(self, **kwargs: typing.Any) -> typing.Tuple[forms.Widget, ...]:
        """Get sub-widgets used by this widget."""
        if self.extension_widgets is not None:  # pragma: no branch
            return self.extension_widgets
        raise ValueError(  # pragma: no cover
            "ExtensionWidget is expected to either set widgets or implement get_widgets()."
        )


class MultipleChoiceExtensionWidget(  # pylint: disable=abstract-method  # is an abstract class
    ExtensionWidget
):
    """Base class for widgets that can be displayed with a simple SelectMultiple widget."""

    def get_widgets(  # type: ignore[override]  # we are more specific here
        self, choices: typing.Sequence[typing.Tuple[str, str]]
    ) -> typing.Tuple[widgets.SelectMultiple]:
        return (widgets.SelectMultiple(choices=choices),)


class ExtendedKeyUsageWidget(MultipleChoiceExtensionWidget):
    """Widget for a :py:class:`~cg:cryptography.x509.ExtendedKeyUsage` extension."""

    def decompress(
        self, value: typing.Optional[x509.Extension[x509.ExtendedKeyUsage]]
    ) -> typing.Tuple[typing.List[str], bool]:
        if value is None:
            return ([], False)
        choices = [EXTENDED_KEY_USAGE_NAMES[usage] for usage in value.value]
        return (choices, value.critical)


class KeyUsageWidget(MultipleChoiceExtensionWidget):
    """Widget for a :py:class:`~cg:cryptography.x509.KeyUsage` extension."""

    def decompress(
        self, value: typing.Optional[x509.Extension[x509.KeyUsage]]
    ) -> typing.Tuple[typing.List[str], bool]:
        if value is None:
            return ([], False)
        choices = []

        # Cannot use a list comprehension here, because cryptography raises ValueError for some attributes
        for choice, name in KEY_USAGE_NAMES.items():
            try:
                chosen = getattr(value.value, choice)
            except ValueError:
                # cryptography raises ValueError for decipher/encipher_only if key_agreement is not set
                chosen = False

            if chosen:
                choices.append(name)

        return (choices, value.critical)


class IssuerAlternativeNameWidget(ExtensionWidget):
    """Widget for a :py:class:`~cg:cryptography.x509.IssuerAlternativeName` extension."""

    extension_widgets = (widgets.Textarea,)

    def decompress(
        self, value: typing.Optional[x509.Extension[x509.IssuerAlternativeName]]
    ) -> typing.Tuple[typing.List[str], bool]:
        if value is None:
            return ("", False)
        general_names = [format_general_name(name) for name in value.value]
        return ("\n".join(general_names), value.critical)


class OCSPNoCheckWidget(ExtensionWidget):
    """Widget for a :py:class:`~cg:cryptography.x509.OCSPNoCheck` extension."""

    extension_widgets = (LabeledCheckboxInput(label=_("included"), wrapper_classes=["include"]),)

    def decompress(
        self, value: typing.Optional[x509.Extension[x509.OCSPNoCheck]]
    ) -> typing.Tuple[bool, bool]:
        if value is None:
            return (False, False)
        return (True, value.critical)


class TLSFeatureWidget(MultipleChoiceExtensionWidget):
    """Widget for a :py:class:`~cg:cryptography.x509.TLSFeature` extension."""

    def decompress(
        self, value: typing.Optional[x509.Extension[x509.TLSFeature]]
    ) -> typing.Tuple[typing.List[str], bool]:
        if value is None:
            return ([], False)
        return ([feature.name for feature in value.value], value.critical)
