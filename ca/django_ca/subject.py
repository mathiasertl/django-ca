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

"""Module for handling x509 subjects."""

import warnings
from collections import abc
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple, Union, cast

from cryptography import x509

from django.core.exceptions import ImproperlyConfigured

from . import ca_settings
from .deprecation import RemovedInDjangoCA123Warning, RemovedInDjangoCA124Warning
from .typehints import ParsableSubject
from .utils import MULTIPLE_OIDS, NAME_OID_MAPPINGS, OID_NAME_MAPPINGS, SUBJECT_FIELDS, parse_name_x509


class Subject:
    """Convenience class to handle X509 Subjects.

    .. deprecated:: 1.22.0

       This class is deprecated and will be removed in ``django-ca==1.24.0``.

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
    ['AT']
    >>> s.setdefault('C', 'DE')
    ['AT']
    >>> s['C'], s['CN']
    ('AT', 'example.com')
    """

    _data: Dict[x509.ObjectIdentifier, List[str]]

    def __init__(self, subject: Optional[ParsableSubject] = None) -> None:
        warnings.warn(
            "django_ca.subject.Subject will be removed in 1.24.0.", category=RemovedInDjangoCA124Warning
        )
        self._data = {}

        iterable: Iterable[
            Tuple[
                Union[x509.ObjectIdentifier, str],
                Union[str, Iterable[str]],
            ]
        ]

        # Normalize input data to a list
        if subject is None:
            iterable = []
        elif isinstance(subject, str):
            iterable = [(n.oid, n.value) for n in parse_name_x509(subject)]  # type: ignore[misc]
        elif isinstance(subject, abc.Mapping):
            iterable = subject.items()
        elif isinstance(subject, x509.Name):
            iterable = [(n.oid, n.value) for n in subject]  # type: ignore[misc]
        elif isinstance(subject, abc.Iterable):
            # TODO: cast should not be necessary, but mypy infers the top-level Union here
            iterable = cast(
                Iterable[Tuple[Union[x509.ObjectIdentifier, str], Union[str, Iterable[str]]]], subject
            )
        else:
            raise ValueError(f"Invalid subject: {subject}")

        for oid, value in iterable:
            if isinstance(oid, str):
                try:
                    oid = NAME_OID_MAPPINGS[oid]
                except KeyError as ex:
                    raise ValueError(f"Invalid OID: {oid}") from ex

            if not value:
                continue

            if oid not in self._data:
                self._data[oid] = [value]
            elif oid not in MULTIPLE_OIDS:
                raise ValueError(f"{OID_NAME_MAPPINGS[oid]}: Must not occur multiple times")
            else:
                self._data[oid].append(value)

    def __contains__(self, oid: Union[str, x509.ObjectIdentifier]) -> bool:
        if isinstance(oid, str):
            oid = NAME_OID_MAPPINGS[oid]
        return oid in self._data

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, Subject) and self._data == other._data

    def __getitem__(self, key: Union[x509.ObjectIdentifier, str]) -> Union[List[str], str]:
        if isinstance(key, str):
            key = NAME_OID_MAPPINGS[key]

        try:
            if key in MULTIPLE_OIDS:
                return self._data[key]
            return self._data[key][0]
        except KeyError as ex:
            raise KeyError(OID_NAME_MAPPINGS[key]) from ex

    def __iter__(self) -> Iterator[str]:
        for key, _value in self._iter:
            yield OID_NAME_MAPPINGS[key]

    def __len__(self) -> int:
        return len(self._data)

    def __setitem__(
        self, key: Union[x509.ObjectIdentifier, str], value: Optional[Union[str, Iterable[str]]]
    ) -> None:
        if isinstance(key, str):
            key = NAME_OID_MAPPINGS[key]

        if not value and key in self._data:
            del self._data[key]
            return
        if isinstance(value, str):
            value = [value]

        elif not isinstance(value, list):
            raise ValueError("Value must be str or list")

        if len(value) > 1 and key not in MULTIPLE_OIDS:
            raise ValueError(f"{OID_NAME_MAPPINGS[key]}: Must not occur multiple times")

        self._data[key] = value

    def __repr__(self) -> str:
        return f'Subject("{str(self)}")'

    def __str__(self) -> str:
        data = []
        for oid, values in self._iter:
            for val in values:
                data.append((oid, val))

        joined_data = "/".join([f"{OID_NAME_MAPPINGS[k]}={v}" for k, v in data])
        return f"/{joined_data}"

    @property
    def _iter(self) -> List[Tuple[x509.ObjectIdentifier, List[str]]]:
        try:
            return sorted(self._data.items(), key=lambda t: SUBJECT_FIELDS.index(t[0]))
        except ValueError:
            # Thrown when subject contains fields that cannot be implicitly sorted
            return list(self._data.items())  # cast to list for uniform return type value

    def clear(self) -> None:
        """Clear the subject."""
        self._data.clear()

    def copy(self) -> "Subject":
        """Create a copy of the subject."""
        return Subject(list(self.items()))

    def get(
        self, key: Union[x509.ObjectIdentifier, str], default: Optional[Union[List[str], str]] = None
    ) -> Optional[Union[List[str], str]]:
        """Return the value for key if key is in the subject, else default."""
        try:
            return self[key]
        except KeyError:
            return default

    def items(self) -> Iterator[Tuple[str, str]]:
        """View of the subjects items."""
        for key, value in self._iter:
            key_str = OID_NAME_MAPPINGS[key]
            for val in value:
                yield key_str, val

    def keys(self) -> Iterator[str]:
        """View on subject keys, in order."""
        for key in self:
            yield key

    def setdefault(
        self, oid: Union[x509.ObjectIdentifier, str], value: Union[str, Iterable[str]]
    ) -> List[str]:
        """Insert key with a value of default if key is not in the subject.

        Return the value for key if key is in the subject, else default.
        """

        if isinstance(oid, str):
            oid = NAME_OID_MAPPINGS[oid]

        if oid in self._data:  # already set
            return self._data[oid]

        if isinstance(value, str):
            value = [value]
        elif not isinstance(value, list):
            raise ValueError("Value must be str or list")

        if len(value) > 1 and oid not in MULTIPLE_OIDS:
            raise ValueError(f"{OID_NAME_MAPPINGS[oid]}: Must not occur multiple times")

        self._data[oid] = value
        return value

    def update(
        self, e: Optional[Union["Subject", ParsableSubject]] = None, **f: Union[str, Iterable[str]]
    ) -> None:
        """Update S from subject/dict/iterable E and F."""
        if e is None:
            e = {}

        # Convert str and x509.Name to plain iterables first
        if isinstance(e, str):
            e = [(n.oid, n.value) for n in parse_name_x509(e)]  # type: ignore[misc]
        elif isinstance(e, x509.Name):
            e = [(n.oid, n.value) for n in e]  # type: ignore[misc]

        if isinstance(e, Subject):
            self._data.update(e._data)  # pylint: disable=protected-access
        elif isinstance(e, abc.Mapping):
            for key, value in e.items():
                self[key] = value
        else:
            for key, value in e:
                self[key] = value

        for k, val in f.items():
            self[k] = val

    def values(self) -> Iterator[str]:
        """View on subject values, in order."""
        for _key, value in self._iter:
            for val in value:
                yield val

    ####################
    # Actual functions #
    ####################
    @property
    def fields(self) -> Iterator[Tuple[x509.ObjectIdentifier, str]]:
        """This subject as a list of :py:class:`~cg:cryptography.x509.oid.NameOID` instances.

        >>> list(Subject('/C=AT/CN=example.com').fields)  # doctest: +NORMALIZE_WHITESPACE
        [(<ObjectIdentifier(oid=2.5.4.6, name=countryName)>, 'AT'),
         (<ObjectIdentifier(oid=2.5.4.3, name=commonName)>, 'example.com')]
        """
        for oid, values in self._iter:
            for val in values:
                yield oid, val

    @property
    def name(self) -> x509.Name:
        """This subject as :py:class:`x509.Name <cg:cryptography.x509.Name>`.

        >>> Subject('/C=AT/CN=example.com').name
        <Name(C=AT,CN=example.com)>
        """
        return x509.Name([x509.NameAttribute(k, v) for k, v in self.fields])


def get_default_subject() -> Subject:  # pragma: no cover
    """Get the default subject as configured by the ``CA_DEFAULT_SUBJECT`` setting.

    .. deprecated:: 1.22.0

       This function will be removed in 1.23.0.
    """

    warnings.warn(
        "django_ca.subject.get_default_subject() will be removed in 1.23.0.",
        category=RemovedInDjangoCA123Warning,
    )

    try:
        return Subject(ca_settings.CA_DEFAULT_SUBJECT)
    except (ValueError, KeyError) as ex:
        raise ImproperlyConfigured(f"CA_DEFAULT_SUBJECT: {ex}") from ex
