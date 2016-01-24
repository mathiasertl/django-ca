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

from collections import OrderedDict

from django import forms

from .widgets import SubjectAltNameWidget
from .widgets import SubjectWidget
from .widgets import BasicConstraintsWidget
from .widgets import KeyUsageWidget

from . import ca_settings


class SubjectField(forms.MultiValueField):
    def __init__(self, *args, **kwargs):
        fields = (
            forms.CharField(required=False),  # C
            forms.CharField(required=False),  # ST
            forms.CharField(required=False),  # L
            forms.CharField(required=False),  # O
            forms.CharField(required=False),  # OU
            forms.CharField(),  # CN
        )
        initial = ca_settings.CA_PROFILES[ca_settings.CA_DEFAULT_PROFILE].get('subject', {})
        kwargs.setdefault('initial', initial)
        kwargs.setdefault('widget', SubjectWidget)
        super(SubjectField, self).__init__(fields=fields, require_all_fields=False,
                                           *args, **kwargs)

    def compress(self, values):
        value = OrderedDict()
        for i, val in enumerate(['C', 'ST', 'L', 'O', 'OU', 'CN']):
            if values[i]:
                value[val] = values[i]
        return value


class SubjectAltNameField(forms.MultiValueField):
    def __init__(self, *args, **kwargs):
        fields = (
            forms.CharField(required=False),
            forms.BooleanField(required=False),
        )
        kwargs.setdefault('widget', SubjectAltNameWidget)
        initial = ca_settings.CA_PROFILES[ca_settings.CA_DEFAULT_PROFILE].get('cn_in_san', True)
        kwargs.setdefault('initial', ['', initial])
        super(SubjectAltNameField, self).__init__(
            fields=fields, require_all_fields=False, *args, **kwargs)

    def compress(self, values):
        return values


class KeyUsageField(forms.MultiValueField):
    def __init__(self, choices, *args, **kwargs):
        label = kwargs['label']
        if ca_settings.CA_DEFAULT_PROFILE:
            initial = ca_settings.CA_PROFILES[ca_settings.CA_DEFAULT_PROFILE][label]
            kwargs.setdefault('initial', [initial['value'], initial['critical']])

        fields = (
            forms.MultipleChoiceField(required=False, choices=choices),
            forms.BooleanField(required=False),
        )
        super(KeyUsageField, self).__init__(
            fields=fields, require_all_fields=False, widget=KeyUsageWidget(choices=choices),
            *args, **kwargs)

    def compress(self, values):
        return values


class BasicConstraintsField(forms.MultiValueField):
    def __init__(self, *args, **kwargs):
        error_messages = {}
        kwargs.setdefault('initial', ['CA:FALSE', '', True])
        choices = (
            ('CA:FALSE', 'CA:FALSE'),
            ('CA:TRUE', 'CA:TRUE'),
        )

        fields = (
            forms.ChoiceField(required=True, choices=choices),
            forms.IntegerField(required=False, min_value=0),
            forms.BooleanField(required=False),
        )
        super(BasicConstraintsField, self).__init__(
            error_messages=error_messages, fields=fields, require_all_fields=False,
            widget=BasicConstraintsWidget(choices), *args, **kwargs)

    def compress(self, values):
        return values
