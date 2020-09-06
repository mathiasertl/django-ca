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

from datetime import date
from datetime import datetime

import idna

from cryptography.hazmat.primitives import hashes

from django import forms
from django.contrib.admin.widgets import AdminDateWidget
from django.contrib.admin.widgets import AdminSplitDateTime
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from . import ca_settings
from .extensions import ExtendedKeyUsage
from .extensions import KeyUsage
from .extensions import TLSFeature
from .fields import MultiValueExtensionField
from .fields import SubjectAltNameField
from .fields import SubjectField
from .models import Certificate
from .utils import EXTENDED_KEY_USAGE_DESC
from .utils import KEY_USAGE_DESC
from .utils import parse_general_name
from .widgets import ProfileWidget


def _initial_expires():
    return datetime.today() + ca_settings.CA_DEFAULT_EXPIRES


def _profile_choices():
    return sorted([(p, p) for p in ca_settings.CA_PROFILES], key=lambda e: e[0])


class X509CertMixinAdminForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        """Override constructor to set the help_text for the pub field.

        The help_text is set by adding a value to the help_texts dictionary of the models Meta
        class. We use this unusual way because it should contain links referencing the currently
        displayed object and the normal methods do not work this way:

        * You cannot use the normal way of setting ``help_texts`` in the forms ``Meta`` class,
          because we cannot reference the object instance here.
        * We cannot access self.fields['pub'] in the constructor, because it is a readonly field
          and thus not present in the form.
        """
        super(X509CertMixinAdminForm, self).__init__(*args, **kwargs)

        if not getattr(self._meta, 'help_texts', None):  # pragma: no cover
            # help_texts is always set since we have a Meta class, but keeping this here as a precaution.
            self._meta.help_texts = {}

        info = self.instance._meta.app_label, self.instance._meta.model_name
        url = reverse('admin:%s_%s_download' % info, kwargs={'pk': self.instance.pk})
        bundle_url = reverse('admin:%s_%s_download_bundle' % info, kwargs={'pk': self.instance.pk})
        self._meta.help_texts['pub'] = _(
            'Download: <a href="%s?format=PEM">as PEM</a> | <a href="%s?format=DER">as DER</a><br />'
            'Certificate bundle: <a href="%s?format=PEM">as PEM</a>'
        ) % (url, url, bundle_url)

    class Meta:
        help_texts = {
            'hpkp_pin': _('''SHA-256 HPKP pin of this certificate. See also
<a href="https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning">HTTP Public Key Pinning</a>
on Wikipedia.'''),
        }


class CreateCertificateBaseForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(CreateCertificateBaseForm, self).__init__(*args, **kwargs)

        # Set choices so we can filter out CAs where the private key does not exist locally
        field = self.fields['ca']
        field.choices = [
            (field.prepare_value(ca), field.label_from_instance(ca))
            for ca in self.fields['ca'].queryset.filter(enabled=True) if ca.key_exists
        ]

    password = forms.CharField(widget=forms.PasswordInput, required=False, help_text=_(
        'Password for the private key. If not given, the private key must be unencrypted.'))
    expires = forms.DateField(initial=_initial_expires, widget=AdminDateWidget())
    subject = SubjectField(label="Subject", required=True)
    subject_alternative_name = SubjectAltNameField(
        label='subjectAltName', required=False,
        help_text=_('''Coma-separated list of alternative names for the certificate.''')
    )
    profile = forms.ChoiceField(
        required=False, widget=ProfileWidget,
        help_text=_('Select a suitable profile or manually select X509 extensions below.'),
        initial=ca_settings.CA_DEFAULT_PROFILE, choices=_profile_choices)
    algorithm = forms.ChoiceField(
        label=_('Signature algorithm'), initial=ca_settings.CA_DIGEST_ALGORITHM.name, choices=[
            ('SHA512', 'SHA-512'),
            ('SHA256', 'SHA-256'),
            ('SHA1', 'SHA-1 (insecure!)'),
            ('MD5', 'MD5 (insecure!)'),
        ],
        help_text=_(
            'Algorithm used for signing the certificate. SHA-512 should be fine in most cases.'
        ),
    )
    autogenerated = forms.BooleanField(required=False,
                                       help_text=_("If this certificate was automatically generated."))
    key_usage = MultiValueExtensionField(help_text=KEY_USAGE_DESC, extension=KeyUsage)
    extended_key_usage = MultiValueExtensionField(
        help_text=EXTENDED_KEY_USAGE_DESC, extension=ExtendedKeyUsage)
    tls_feature = MultiValueExtensionField(extension=TLSFeature)

    def clean_algorithm(self):
        algo = self.cleaned_data['algorithm']
        try:
            algo = getattr(hashes, algo.upper())()
        except AttributeError:  # pragma: no cover
            # We only add what is known to cryptography in `choices`, and other values posted are caught
            # during Djangos standard form validation, so this should never happen.
            raise forms.ValidationError(_('Unknown hash algorithm: %s') % algo)
        return algo

    def clean_expires(self):
        expires = self.cleaned_data['expires']
        if expires < date.today():
            raise forms.ValidationError(_('Certificate cannot expire in the past.'))
        return expires

    def clean_password(self):
        password = self.cleaned_data['password']
        if not password:
            return None
        return password.encode('utf-8')

    def clean(self):
        data = super(CreateCertificateBaseForm, self).clean()
        expires = data.get('expires')
        ca = data.get('ca')
        password = data.get('password')
        subject = data.get('subject')
        cn_in_san = data.get('subject_alternative_name')[1]

        # test the password
        try:
            ca.key(password)
        except Exception as e:
            self.add_error('password', str(e))

        if cn_in_san and subject and subject.get('CN'):
            try:
                parse_general_name(subject['CN'])
            except idna.IDNAError:
                self.add_error('subject_alternative_name',
                               _('The CommonName cannot be parsed as general name. Either change the '
                                 'CommonName or do not include it.'))

        if ca and expires and ca.expires.date() < expires:
            stamp = ca.expires.strftime('%Y-%m-%d')
            self.add_error('expires', _(
                'CA expires on %s, certificate must not expire after that.') % stamp)
        return data

    class Meta:
        model = Certificate
        fields = ['watchers', 'ca', ]


class CreateCertificateForm(CreateCertificateBaseForm):
    def clean_csr(self):
        data = self.cleaned_data['csr']
        lines = data.splitlines()
        if not lines or lines[0] != '-----BEGIN CERTIFICATE REQUEST-----' \
                or lines[-1] != '-----END CERTIFICATE REQUEST-----':
            raise forms.ValidationError(_("Enter a valid CSR (in PEM format)."))

        return data

    class Meta:
        model = Certificate
        fields = ['csr', 'watchers', 'ca', ]
        help_texts = {
            'csr': _('''The Certificate Signing Request (CSR) in PEM format. To create a new one:
<span class="shell">openssl genrsa -out hostname.key 4096
openssl req -new -key hostname.key -out hostname.csr -utf8 -batch \\
                     -subj '/CN=hostname/emailAddress=root@hostname'
</span>'''),
        }


class ResignCertificateForm(CreateCertificateBaseForm):
    pass


class RevokeCertificateForm(forms.ModelForm):
    class Media:
        js = (
            # jquery/core.js for the datetime widgets:
            'admin/js/vendor/jquery/jquery.js',
            'admin/js/jquery.init.js',
            'admin/js/core.js',
        )

    class Meta:
        model = Certificate
        fields = ['revoked_reason', 'compromised']
        field_classes = {
            'compromised': forms.SplitDateTimeField,
        }
        widgets = {
            'compromised': AdminSplitDateTime,
        }
