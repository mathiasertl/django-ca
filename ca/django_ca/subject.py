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

import six

from .utils import MULTIPLE_OIDS
from .utils import OID_NAME_MAPPINGS
from .utils import NAME_OID_MAPPINGS
from .utils import parse_name
from .utils import sort_name


@six.python_2_unicode_compatible
class Subject(object):
    def __init__(self, subject):
        self._data = {}

        # Normalize input data to a list
        if isinstance(subject, six.string_types):
            subject = parse_name(subject)
        elif isinstance(subject, dict):
            subject = subject.items()
        elif not isinstance(subject, (list, tuple)):
            raise ValueError('subject: not a list/tuple.')

        for oid, value in subject:
            if isinstance(oid, six.string_types):
                oid = NAME_OID_MAPPINGS[oid]

            if oid not in self._data:
                self._data[oid] = [value]
            elif oid not in MULTIPLE_OIDS:
                raise ValueError('%s: Must not occur multiple times' % OID_NAME_MAPPINGS[oid])
            else:
                self._data[oid].append(value)

    def __eq__(self, other):
        return isinstance(other, Subject) and self._data == other._data

    def __str__(self):
        data = []
        for oid, values in self._data.items():
            for val in values:
                data.append((OID_NAME_MAPPINGS[oid], val))

        data = ['%s=%s' % (k, v) for k, v in sort_name(data)]
        return '/%s' % '/'.join(data)

    def __len__(self):
        return len(self._data)

    def setdefault(self, oid, value):
        if isinstance(oid, six.string_types):
            oid = NAME_OID_MAPPINGS[oid]

        if oid in self._data:  # already set
            return

        if isinstance(value, six.string_types):
            value = [value]
        elif not isinstance(value, list):
            raise ValueError('Default must be str or list')

        if len(value) > 1 and oid not in MULTIPLE_OIDS:
            raise ValueError('%s: Must not occur multiple times' % OID_NAME_MAPPINGS[oid])

        self._data[oid] = value
