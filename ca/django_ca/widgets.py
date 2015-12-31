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

import re

from django.forms import widgets


class BasicConstraintsWidget(widgets.MultiWidget):
    def __init__(self, attrs=None):
        _widgets = (
            widgets.CheckboxInput(attrs=attrs),
            widgets.CheckboxInput(attrs=attrs),
            widgets.TextInput(attrs=attrs),
        )
        super(BasicConstraintsWidget, self).__init__(_widgets, attrs)

    def decompress(self, value):
        if value:
            critical, value = value
            match = re.match('CA:(?P<ca>TRUE|FALSE)(,pathlen:(?P<pathlen>[0-9]))?', value)
            ca = match.group('ca') == 'TRUE'
            pathlen = match.group('pathlen')

            if pathlen is None or ca is False:
                pathlen = ''

            return [critical, ca, pathlen]
        return [False, False, '']
