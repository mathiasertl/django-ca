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


class BasicConstraintsField(forms.MultiValueField):
    def __init__(self, *args, **kwargs):
        error_messages = {}
        kwargs.setdefault('initial', [True, False, ''])

        fields = (
            forms.BooleanField(label="Critical", required=False),
            forms.BooleanField(label="CA certificate", required=False),
            forms.IntegerField(min_value=0, label="Path length", required=False),
        )
        super(BasicConstraintsField, self).__init__(
            error_messages=error_messages, fields=fields, require_all_fields=False,
            widget=BasicConstraintsWidget, *args, **kwargs)

    def compress(self, values):
        value = ''
        critical, ca, pathlen = values
        if ca:
            value += 'CA:TRUE'
        else:
            value += 'CA:FALSE'

        if ca and pathlen is not None:
            value += ',pathlen:%s' % pathlen
        return (critical, value)
