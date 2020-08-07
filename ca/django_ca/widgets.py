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

from django.forms import widgets
from django.utils.encoding import force_str
from django.utils.translation import gettext as _

from . import ca_settings


class LabeledCheckboxInput(widgets.CheckboxInput):
    """CheckboxInput widget that adds a label and wraps everything in a <span />.

    This is necessary because widgets in MultiValueFields don't render with a label."""

    template_name = 'django_ca/forms/widgets/labeledcheckboxinput.html'

    def __init__(self, label, *args, **kwargs):
        self.label = label
        super(LabeledCheckboxInput, self).__init__(*args, **kwargs)

    def get_context(self, *args, **kwargs):
        ctx = super(LabeledCheckboxInput, self).get_context(*args, **kwargs)
        ctx['widget']['label'] = self.label
        return ctx

    class Media:
        css = {
            'all': ('django_ca/admin/css/labeledcheckboxinput.css', ),
        }


class LabeledTextInput(widgets.TextInput):
    """CheckboxInput widget that adds a label and wraps everything in a <span />.

    This is necessary because widgets in MultiValueFields don't render with a label."""

    template_name = 'django_ca/forms/widgets/labeledtextinput.html'

    def __init__(self, label, *args, **kwargs):
        self.label = label
        super(LabeledTextInput, self).__init__(*args, **kwargs)

    def get_context(self, *args, **kwargs):
        ctx = super(LabeledTextInput, self).get_context(*args, **kwargs)
        ctx['widget']['label'] = self.label
        ctx['widget']['cssid'] = self.label.lower().replace(' ', '-')
        return ctx

    class Media:
        css = {
            'all': ('django_ca/admin/css/labeledtextinput.css', ),
        }


class SubjectTextInput(LabeledTextInput):
    template_name = 'django_ca/forms/widgets/subjecttextinput.html'


class ProfileWidget(widgets.Select):
    # TODO: shouldn't we set a template_name here? Perhaps that's why render() is still called

    def render(self, name, value, attrs=None, renderer=None):
        html = super(ProfileWidget, self).render(name, value, attrs=attrs, renderer=renderer)

        # add the description of the default selected profile as help text (will be updated by JS when
        # different profile is selected)
        desc = ca_settings.CA_PROFILES[ca_settings.CA_DEFAULT_PROFILE].get(
            'description', ca_settings.CA_PROFILES[ca_settings.CA_DEFAULT_PROFILE].get('desc', ''))
        html += '<p class="help profile-desc">%s</p>' % force_str(desc)

        return html

    class Media:
        js = (
            'admin/js/jquery.init.js',
            'django_ca/admin/js/profilewidget.js',
        )


class CustomMultiWidget(widgets.MultiWidget):
    """Wraps the multi widget into a <p> element."""

    template_name = 'django_ca/forms/widgets/custommultiwidget.html'


class SubjectWidget(CustomMultiWidget):
    def __init__(self, attrs=None):
        _widgets = (
            SubjectTextInput(label=_('Country'), attrs={'placeholder': '2 character country code'}),
            SubjectTextInput(label=_('State')),
            SubjectTextInput(label=_('Location')),
            SubjectTextInput(label=_('Organization')),
            SubjectTextInput(label=_('Organizational Unit')),
            SubjectTextInput(label=_('CommonName'), attrs={'required': True}),
            SubjectTextInput(label=_('E-Mail')),
        )
        super(SubjectWidget, self).__init__(_widgets, attrs)

    def decompress(self, value):
        if value is None:  # pragma: no cover
            return ('', '', '', '', '', '')

        # Multiple OUs are not supported in webinterface
        ou = value.get('OU', '')
        if isinstance(ou, list) and ou:
            ou = ou[0]

        # Used e.g. for initial form data (e.g. resigning a cert)
        return [
            value.get('C', ''),
            value.get('ST', ''),
            value.get('L', ''),
            value.get('O', ''),
            ou,
            value.get('CN', ''),
            value.get('emailAddress', ''),
        ]


class SubjectAltNameWidget(CustomMultiWidget):
    def __init__(self, attrs=None):
        _widgets = (
            widgets.TextInput(),
            LabeledCheckboxInput(label="Include CommonName")
        )
        super(SubjectAltNameWidget, self).__init__(_widgets, attrs)

    def decompress(self, value):  # pragma: no cover
        if value:
            return value
        return ('', True)


class MultiValueExtensionWidget(CustomMultiWidget):
    def __init__(self, choices, attrs=None):
        _widgets = (
            widgets.SelectMultiple(choices=choices, attrs=attrs),
            LabeledCheckboxInput(label=_('critical')),
        )
        super(MultiValueExtensionWidget, self).__init__(_widgets, attrs)

    def decompress(self, value):
        if value:
            return value.serialize_iterable(), value.critical
        return ([], False)
