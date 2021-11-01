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

"""Django form fields related to django-ca."""

import typing

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import NameOID

from django import forms
from django.utils.safestring import mark_safe
from django.utils.translation import gettext_lazy as _

from .extensions import Extension
from .profiles import profile
from .utils import ADMIN_SUBJECT_OIDS
from .widgets import MultiValueExtensionWidget
from .widgets import SubjectAltNameWidget
from .widgets import SubjectWidget

if typing.TYPE_CHECKING:
    from .modelfields import LazyCertificateSigningRequest


class CertificateSigningRequestField(forms.CharField):
    """A form field for `~cg:cryptography.x509.CertificateSigningRequest` encoded as PEM."""

    start = "-----BEGIN CERTIFICATE REQUEST-----"
    end = "-----END CERTIFICATE REQUEST-----"
    simple_validation_error = _(
        "Could not parse PEM-encoded CSR. They usually look like this: <pre>%(start)s\n...\n%(end)s</pre>"
    ) % {"start": start, "end": end}

    def __init__(self, **kwargs: typing.Any) -> None:
        # COVERAGE NOTE: Below condition is never false, as we never pass a custom help text.
        if not kwargs.get("help_text"):  # pragma: no branch
            kwargs["help_text"] = _(
                """The Certificate Signing Request (CSR) in PEM format. To create a new one:
<span class="shell">openssl genrsa -out hostname.key 4096
openssl req -new -key hostname.key -out hostname.csr -utf8 -batch \\
                     -subj '/CN=hostname/emailAddress=root@hostname'
</span>"""
            )
        if not kwargs.get("widget"):  # pragma: no branch # we never pass a custom widget
            kwargs["widget"] = forms.Textarea
        super().__init__(**kwargs)
        self.widget.attrs.update({"cols": "64"})

    def prepare_value(
        self, value: typing.Optional[typing.Union[str, "LazyCertificateSigningRequest"]]
    ) -> str:
        """Prepare a value to a form that can be shown in HTML.

        Unfortunately this function is not documented by Django at all but is called when a form is rendered.

        This function receives ``None`` when viewing an initial form for a new instance. If form validation
        fails, it receives the string as posted by the user (which might be an invalid string). When viewing
        an existing certificate, it will receive the LazyField instance of the object.
        """
        if value is None:  # for new objects
            return ""
        if isinstance(value, str):  # when form validation fails
            return value

        # COVERAGE NOTE: This would happen if the field is editable, but is always read-only.
        return value.pem  # pragma: no cover

    # TYPE NOTE: django-stubs typehints this as Optional[Any], but we only ever observed receiving ``str``.
    def to_python(self, value: str) -> x509.CertificateSigningRequest:  # type: ignore[override]
        """Coerce given str to correct data type, raises ValidationError if not possible.

        This function is called during form validation.
        """
        if not value.startswith(self.start) or not value.strip().endswith(self.end):
            raise forms.ValidationError(mark_safe(self.simple_validation_error))
        try:
            return x509.load_pem_x509_csr(value.encode("utf-8"), default_backend())
        except ValueError as ex:
            raise forms.ValidationError(ex) from ex


class SubjectField(forms.MultiValueField):
    """A MultiValue field for a :py:class:`~django_ca.subject.Subject`."""

    required_oids = (NameOID.COMMON_NAME,)

    def __init__(self, **kwargs: typing.Any) -> None:
        fields = tuple(forms.CharField(required=v in self.required_oids) for v in ADMIN_SUBJECT_OIDS)

        # NOTE: do not pass initial here as this is done on webserver invocation
        #       This screws up tests.
        kwargs.setdefault("widget", SubjectWidget)
        super().__init__(fields=fields, require_all_fields=False, **kwargs)

    def compress(self, data_list: typing.List[str]) -> x509.Name:
        # list comprehension is to filter empty fields
        return x509.Name(
            [x509.NameAttribute(oid, value) for oid, value in zip(ADMIN_SUBJECT_OIDS, data_list) if value]
        )


class SubjectAltNameField(forms.MultiValueField):
    """A MultiValueField for a Subject Alternative Name extension."""

    def __init__(self, **kwargs: typing.Any) -> None:
        fields = (
            forms.CharField(required=False),
            forms.BooleanField(required=False),
        )
        kwargs.setdefault("widget", SubjectAltNameWidget)
        kwargs.setdefault("initial", ["", profile.cn_in_san])
        super().__init__(fields=fields, require_all_fields=False, **kwargs)

    def compress(self, data_list: typing.Tuple[str, bool]) -> typing.Tuple[str, bool]:
        return data_list


class MultiValueExtensionField(forms.MultiValueField):
    """A MultiValueField for multiple-choice extensions (e.g. :py:class:`~django_ca.extensions.KeyUsage`."""

    def __init__(
        self, extension: typing.Type[Extension[typing.Any, typing.Any, typing.Any]], **kwargs: typing.Any
    ) -> None:
        self.extension = extension
        kwargs.setdefault("label", extension.name)
        ext = profile.extensions.get(self.extension.key)
        if ext:
            ext = ext.serialize()
            kwargs.setdefault("initial", [ext["value"], ext["critical"]])

        # NOTE: only use extensions that define CHOICES
        choices: typing.Tuple[typing.Tuple[str, str], ...] = extension.CHOICES  # type: ignore[attr-defined]
        fields = (
            forms.MultipleChoiceField(required=False, choices=choices),
            forms.BooleanField(required=False),
        )

        widget = MultiValueExtensionWidget(choices=choices)
        super().__init__(fields=fields, require_all_fields=False, widget=widget, **kwargs)

    def compress(
        self, data_list: typing.Tuple[typing.List[str], bool]
    ) -> Extension[typing.Any, typing.Any, typing.Any]:
        return self.extension(
            {
                "critical": data_list[1],
                "value": data_list[0],
            }
        )
