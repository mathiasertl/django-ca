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

from django import forms

from .widgets import BasicConstraintsWidget
from .widgets import KeyUsageWidget


class KeyUsageField(forms.MultiValueField):
    def __init__(self, choices, *args, **kwargs):
        kwargs.setdefault('initial', [[], True])
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
        kwargs.setdefault('initial', [False, '', True])

        fields = (
            forms.BooleanField(required=False),
            forms.IntegerField(required=False, min_value=0),
            forms.BooleanField(required=False),
        )
        super(BasicConstraintsField, self).__init__(
            error_messages=error_messages, fields=fields, require_all_fields=False,
            widget=BasicConstraintsWidget, *args, **kwargs)

    def compress(self, values):
        value = ''
        ca, pathlen, critical = values
        if ca:
            value += 'CA:TRUE'
        else:
            value += 'CA:FALSE'

        if ca and pathlen is not None:
            value += ',pathlen:%s' % pathlen
        return (critical, value)
