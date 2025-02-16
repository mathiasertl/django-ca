# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca. If not, see
# <http://www.gnu.org/licenses/>.

"""Add an autodoc extension to document key/value mappings.

.. seealso:: https://www.sphinx-doc.org/en/master/development/tutorials/autodoc_ext.html
"""

from collections.abc import Mapping
from typing import Any

from docutils.statemachine import StringList
from sphinx.ext.autodoc import DataDocumenter, ObjectMember
from tabulate import tabulate

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID,
    ExtensionOID,
    NameOID,
    SubjectInformationAccessOID,
)


class MappingDocumentor(DataDocumenter):
    """Documentor for key/value mappings."""

    objtype = "mapping"
    directivetype = DataDocumenter.objtype

    # NOTE: we want this to be LOWER, because otherwise the class-documentor will use this class for **any**
    # attribute that gets documented via the :members: directive.
    priority = DataDocumenter.priority - 10

    def get_object_members(self, want_all: bool) -> tuple[bool, list[ObjectMember]]:
        """Overwritten from base class."""
        return False, []

    @classmethod
    def can_document_member(cls, member: Any, membername: str, isattr: bool, parent: Any) -> bool:
        """Determine if this documentor can document the given variable."""
        return super().can_document_member(member, membername, isattr, parent) and isinstance(member, Mapping)

    def serialize_object_identifier(self, value: x509.ObjectIdentifier) -> str:
        """Serialize an object identifier."""
        for name in dir(ExtensionOID):
            if value == getattr(ExtensionOID, name):
                return f":py:attr:`ExtensionOID.{name} <cg:cryptography.x509.oid.ExtensionOID.{name}>`"

        # Return undocumented OIDs as strings.
        for oid_name in ("INN", "OGRN", "SNILS"):
            if value == getattr(NameOID, oid_name):
                return f"``NameOID.{oid_name}``"

        for name in dir(NameOID):
            if value == getattr(NameOID, name):
                return f":py:attr:`NameOID.{name} <cg:cryptography.x509.oid.NameOID.{name}>`"

        for name in dir(AuthorityInformationAccessOID):
            if value == getattr(AuthorityInformationAccessOID, name):
                return (
                    f":py:attr:`AuthorityInformationAccessOID.{name} "
                    f"<cg:cryptography.x509.oid.AuthorityInformationAccessOID.{name}>`"
                )

        for name in dir(SubjectInformationAccessOID):
            if value == getattr(SubjectInformationAccessOID, name):
                return (
                    f":py:attr:`SubjectInformationAccessOID.{name} "
                    f"<cg:cryptography.x509.oid.SubjectInformationAccessOID.{name}>`"
                )

        for name in dir(ExtendedKeyUsageOID):
            if value == getattr(ExtendedKeyUsageOID, name):
                return (
                    f":py:attr:`ExtendedKeyUsageOID.{name} "
                    f"<cg:cryptography.x509.oid.ExtendedKeyUsageOID.{name}>`"
                )

        return f'``"{value.dotted_string}"``'  # return dotted string as default

    def serialize_value(self, value: Any) -> str:
        """Serialize a value (or key) into a string as displayed in the table."""
        if isinstance(value, bool):
            return f"``{value}``"
        if isinstance(value, str):
            return f'``"{value}"``'
        if isinstance(value, type) and issubclass(
            value, (hashes.HashAlgorithm, ec.EllipticCurve, x509.GeneralName)
        ):
            return f":py:class:`~cg:{value.__module__}.{value.__name__}`"
        if isinstance(value, x509.ObjectIdentifier):
            return self.serialize_object_identifier(value)

        # Unknown types are marked as inline code with the full class path.
        if isinstance(value, type):
            return f"``{value.__module__}.{value.__name__}``"
        if isinstance(value, x509.TLSFeatureType):
            return f":py:attr:`~cg:cryptography.x509.TLSFeatureType.{value.name}`"

        return str(value)

    def add_table(self) -> None:
        """Add the RST table of the mapping to the description."""
        source_name = self.get_sourcename()
        self.add_line("", source_name)

        lines = []
        for key, value in self.object.items():
            lines.append([self.serialize_value(key), self.serialize_value(value)])

        # Finally, create rst table
        table = tabulate(sorted(lines), headers=["Key", "Value"], tablefmt="rst")

        for line in table.splitlines():
            self.add_line(line, source_name)

    def add_content(self, more_content: StringList | None) -> None:
        """Overwritten to add a table of values for a mapping to the description."""
        super().add_content(more_content)
        self.add_table()
