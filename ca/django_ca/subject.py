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

from cryptography import x509

from .utils import MULTIPLE_OIDS
from .utils import OID_NAME_MAPPINGS
from .utils import NAME_OID_MAPPINGS
from .utils import SUBJECT_FIELDS
from .utils import parse_name
from .utils import sort_name


@six.python_2_unicode_compatible
class Subject(object):
    def __init__(self, subject=None):
        self._data = {}

        # Normalize input data to a list
        if subject is None:
            subject = []
        elif isinstance(subject, six.string_types):
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

    def __contains__(self, oid):
        if isinstance(oid, six.string_types):
            oid = NAME_OID_MAPPINGS[oid]
        return oid in self._data

    def __eq__(self, other):
        return isinstance(other, Subject) and self._data == other._data

    def __getitem__(self, key):
        if isinstance(key, six.string_types):
            key = NAME_OID_MAPPINGS[key]

        try:
            if key in MULTIPLE_OIDS:
                return self._data[key]
            return self._data[key][0]
        except KeyError:
            raise KeyError(OID_NAME_MAPPINGS[key])

    def __len__(self):
        return len(self._data)

    def __setitem__(self, key, value):
        if isinstance(key, six.string_types):
            key = NAME_OID_MAPPINGS[key]

        if isinstance(value, six.string_types):
            value = [value]
        elif not isinstance(value, list):
            raise ValueError('Value must be str or list')

        if len(value) > 1 and key not in MULTIPLE_OIDS:
            raise ValueError('%s: Must not occur multiple times' % OID_NAME_MAPPINGS[key])

        self._data[key] = value

    def __repr__(self):
        return 'Subject("%s")' % str(self)

    def __str__(self):
        data = []
        for oid, values in self._data.items():
            for val in values:
                data.append((OID_NAME_MAPPINGS[oid], val))

        data = ['%s=%s' % (k, v) for k, v in sort_name(data)]
        return '/%s' % '/'.join(data)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def setdefault(self, oid, value):
        if isinstance(oid, six.string_types):
            oid = NAME_OID_MAPPINGS[oid]

        if oid in self._data:  # already set
            return

        if isinstance(value, six.string_types):
            value = [value]
        elif not isinstance(value, list):
            raise ValueError('Value must be str or list')

        if len(value) > 1 and oid not in MULTIPLE_OIDS:
            raise ValueError('%s: Must not occur multiple times' % OID_NAME_MAPPINGS[oid])

        self._data[oid] = value

    ####################
    # Actual functions #
    ####################
    @property
    def fields(self):
        _sort = sorted(self._data.items(), key=lambda t: SUBJECT_FIELDS.index(OID_NAME_MAPPINGS[t[0]]))
        for oid, values in _sort:
            for val in values:
                yield oid, val

    @property
    def name(self):
        """This subject as :py:class:`x509.Name <cryptography:cryptography.x509.Name>`.

        >>> Subject('/C=AT/CN=example.com').name  # doctest: +NORMALIZE_WHITESPACE
        <Name([<NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.6, name=countryName)>, value='AT')>,
               <NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.3, name=commonName)>, value='example.com')>])>
        """
        return x509.Name([x509.NameAttribute(k, v) for k, v in self.fields])
