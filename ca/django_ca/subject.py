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

from cryptography import x509

from django.core.exceptions import ImproperlyConfigured
from django.utils.encoding import force_str

from . import ca_settings
from .utils import MULTIPLE_OIDS
from .utils import NAME_OID_MAPPINGS
from .utils import OID_NAME_MAPPINGS
from .utils import SUBJECT_FIELDS
from .utils import parse_name
from .utils import sort_name


class Subject(object):
    """Convenience class to handle X509 Subjects.

    This class accepts a variety of values and intelligently parses them:

    >>> Subject('/CN=example.com')
    Subject("/CN=example.com")
    >>> Subject({'CN': 'example.com'})
    Subject("/CN=example.com")
    >>> Subject([('CN', 'example.com'), ])
    Subject("/CN=example.com")

    In most respects, this class handles like a ``dict``:

    >>> s = Subject('/CN=example.com')
    >>> 'CN' in s
    True
    >>> s.get('OU', 'Default OU')
    'Default OU'
    >>> s.setdefault('C', 'AT')
    >>> s['C'], s['CN']
    ('AT', 'example.com')
    """

    def __init__(self, subject=None):
        self._data = {}

        # Normalize input data to a list
        if subject is None:
            subject = []
        elif isinstance(subject, str):
            subject = parse_name(subject)
        elif isinstance(subject, dict):
            subject = subject.items()
        elif isinstance(subject, x509.Name):
            subject = [(n.oid, n.value) for n in subject]
        elif not isinstance(subject, (list, tuple)):
            raise ValueError('Invalid subject: %s' % subject)

        for oid, value in subject:
            if isinstance(oid, str):
                try:
                    oid = NAME_OID_MAPPINGS[oid]
                except KeyError:
                    raise ValueError('Invalid OID: %s' % oid)

            if not value:
                continue

            if oid not in self._data:
                self._data[oid] = [value]
            elif oid not in MULTIPLE_OIDS:
                raise ValueError('%s: Must not occur multiple times' % OID_NAME_MAPPINGS[oid])
            else:
                self._data[oid].append(value)

    def __contains__(self, oid):
        if isinstance(oid, str):
            oid = NAME_OID_MAPPINGS[oid]
        return oid in self._data

    def __eq__(self, other):
        return isinstance(other, Subject) and self._data == other._data

    def __getitem__(self, key):
        if isinstance(key, str):
            key = NAME_OID_MAPPINGS[key]

        try:
            if key in MULTIPLE_OIDS:
                return self._data[key]
            return self._data[key][0]
        except KeyError:
            raise KeyError(OID_NAME_MAPPINGS[key])

    def __iter__(self):
        #return (OID_NAME_MAPPINGS[t[0]] for t in self._iter)
        for key, value in self._iter:
            for val in value:
                yield OID_NAME_MAPPINGS[key]

    def __len__(self):
        return len(self._data)

    def __setitem__(self, key, value):
        if isinstance(key, str):
            key = NAME_OID_MAPPINGS[key]

        if not value and key in self._data:
            del self._data[key]
            return
        elif isinstance(value, str):
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

    @property
    def _iter(self):
        return sorted(self._data.items(), key=lambda t: SUBJECT_FIELDS.index(OID_NAME_MAPPINGS[t[0]]))

    def clear(self):
        self._data.clear()

    def copy(self):
        return Subject(list(self.items()))

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def items(self):
        for key, value in self._iter:
            key = OID_NAME_MAPPINGS[key]
            for val in value:
                yield key, val

    def keys(self):
        for key in self:
            yield key

    def setdefault(self, oid, value):
        if isinstance(oid, str):
            oid = NAME_OID_MAPPINGS[oid]

        if oid in self._data:  # already set
            return

        if isinstance(value, str):
            value = [value]
        elif not isinstance(value, list):
            raise ValueError('Value must be str or list')

        if len(value) > 1 and oid not in MULTIPLE_OIDS:
            raise ValueError('%s: Must not occur multiple times' % OID_NAME_MAPPINGS[oid])

        self._data[oid] = value

    def update(self, e=None, **f):
        if e is None:
            e = {}

        if isinstance(e, Subject):
            self._data.update(e._data)
        elif hasattr(e, 'keys'):
            for k in e.keys():
                self[k] = e[k]
        else:
            for k, v in e:
                self[k] = v

        for k in f:
            self[k] = f[k]

    def values(self):
        for key, value in self._iter:
            for val in value:
                yield val

    ####################
    # Actual functions #
    ####################
    @property
    def fields(self):
        """This subject as a list of :py:class:`~cg:cryptography.x509.oid.NameOID` instances.

        >>> list(Subject('/C=AT/CN=example.com').fields)  # doctest: +NORMALIZE_WHITESPACE
        [(<ObjectIdentifier(oid=2.5.4.6, name=countryName)>, 'AT'),
         (<ObjectIdentifier(oid=2.5.4.3, name=commonName)>, 'example.com')]
        """
        for oid, values in self._iter:
            for val in values:
                yield oid, force_str(val)

    @property
    def name(self):
        """This subject as :py:class:`x509.Name <cg:cryptography.x509.Name>`.

        >>> Subject('/C=AT/CN=example.com').name
        <Name(C=AT,CN=example.com)>
        """
        return x509.Name([x509.NameAttribute(k, v) for k, v in self.fields])


def get_default_subject():
    try:
        return Subject(ca_settings.CA_DEFAULT_SUBJECT)
    except (ValueError, KeyError) as e:
        raise ImproperlyConfigured('CA_DEFAULT_SUBJECT: %s' % e)
