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

from . import ca_settings
from .utils import SUBJECT_FIELDS
from .widgets import KeyUsageWidget
from .widgets import SubjectAltNameWidget
from .widgets import SubjectWidget


class SubjectField(forms.MultiValueField):
    def __init__(self, *args, **kwargs):
        fields = (
            forms.CharField(required=False),  # C
            forms.CharField(required=False),  # ST
            forms.CharField(required=False),  # L
            forms.CharField(required=False),  # O
            forms.CharField(required=False),  # OU
            forms.CharField(),  # CN
            forms.CharField(required=False),  # E
        )
        initial = ca_settings.CA_PROFILES[ca_settings.CA_DEFAULT_PROFILE].get('subject', {})
        kwargs.setdefault('initial', initial)
        kwargs.setdefault('widget', SubjectWidget)
        super(SubjectField, self).__init__(fields=fields, require_all_fields=False,
                                           *args, **kwargs)

    def compress(self, values):
        # list comprehension is to filter empty fields
        return OrderedDict([(k, v) for k, v in zip(SUBJECT_FIELDS, values) if v])


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
