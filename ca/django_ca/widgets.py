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

import json

from django.forms import widgets
from django.utils.encoding import force_text
from django.utils.translation import ugettext as _

from . import ca_settings
from .utils import LazyEncoder


class LabeledCheckboxInput(widgets.CheckboxInput):
    """CheckboxInput widget that adds a label and wraps everything in a <span />.

    This is necessary because widgets in MultiValueFields don't render with a label."""

    def __init__(self, label, *args, **kwargs):
        self.label = label
        super(LabeledCheckboxInput, self).__init__(*args, **kwargs)

    def render(self, name, value, attrs=None):
        html = super(LabeledCheckboxInput, self).render(name, value, attrs=attrs)
        label = '<label for="%s">%s</label>' % (attrs.get('id'), self.label)
        html = '<span class="critical-widget-wrapper">%s%s</span>' % (html, label)
        return html

    class Media:
        css = {
            'all': ('django_ca/admin/css/labeledcheckboxinput.css', ),
        }


class LabeledTextInput(widgets.TextInput):
    """CheckboxInput widget that adds a label and wraps everything in a <span />.

    This is necessary because widgets in MultiValueFields don't render with a label."""

    def __init__(self, label, *args, **kwargs):
        self.label = label
        super(LabeledTextInput, self).__init__(*args, **kwargs)

    def render_wrapped(self, name, value, attrs):
        html = super(LabeledTextInput, self).render(name, value, attrs=attrs)
        required = ''
        if self.attrs.get('required', False):
            required = 'class="required" '

        html += '<label %sfor="%s">%s</label>' % (required, attrs.get('id'), self.label)

        return html

    def render(self, name, value, attrs=None):
        html = self.render_wrapped(name, value, attrs)
        cssid = self.label.lower().replace(' ', '-')
        html = '<span id="%s" class="labeled-text-multiwidget">%s</span>' % (cssid, html)
        return html

    class Media:
        css = {
            'all': ('django_ca/admin/css/labeledtextinput.css', ),
        }


class SubjectTextInput(LabeledTextInput):
    def render_wrapped(self, name, value, attrs):
        html = super(SubjectTextInput, self).render_wrapped(name, value, attrs)
        html += '<span class="from-csr">%s <span></span></span>' % _('from CSR:')
        return html


class ProfileWidget(widgets.Select):
    def render(self, name, value, attrs=None):
        html = super(ProfileWidget, self).render(name, value, attrs=attrs)
        html += '''<script type="text/javascript">
            var ca_profiles = %s;
        </script>''' % json.dumps(ca_settings.CA_PROFILES, cls=LazyEncoder)
        html += '<p class="help profile-desc">%s</p>' % force_text(
            ca_settings.CA_PROFILES[ca_settings.CA_DEFAULT_PROFILE]['desc'])
        return html

    class Media:
        js = (
            'django_ca/admin/js/profilewidget.js',
        )


class CustomMultiWidget(widgets.MultiWidget):
    """Wraps the multi widget into a <p> element."""

    def format_output(self, rendered_widgets):
        # NOTE: We use a <p> because djangos stock forms.css takes care of indent this way.
        rendered_widgets.insert(0, '<p class="multi-widget">')
        rendered_widgets.append('</p>')
        return ''.join(rendered_widgets)


class SubjectWidget(CustomMultiWidget):
    def __init__(self, attrs=None):
        _widgets = (
            SubjectTextInput(label=_('Country')),
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
        return [
            value.get('C', ''),
            value.get('ST', ''),
            value.get('L', ''),
            value.get('O', ''),
            value.get('OU', ''),
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


class KeyUsageWidget(CustomMultiWidget):
    def __init__(self, choices, attrs=None):
        _widgets = (
            widgets.SelectMultiple(choices=choices, attrs=attrs),
            LabeledCheckboxInput(label=_('critical')),
        )
        super(KeyUsageWidget, self).__init__(_widgets, attrs)

    def decompress(self, value):  # pragma: no cover
        if value:
            return value
        return ([], True)
