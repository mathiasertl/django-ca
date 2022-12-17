# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca. If not,
# see <http://www.gnu.org/licenses/>.

"""Add an autodoc extension to document key/value mappings.

.. seealso:: https://www.sphinx-doc.org/en/master/development/tutorials/autodoc_ext.html
"""

from collections.abc import Mapping
from typing import Any, Optional

from docutils.statemachine import StringList
from sphinx.ext.autodoc import DataDocumenter
from tabulate import tabulate

from cryptography import x509
from cryptography.x509.oid import ExtensionOID


class MappingDocumentor(DataDocumenter):
    """Documentor for key/value mappings."""

    objtype = "mapping"
    directivetype = DataDocumenter.objtype

    # NOTE: we want this to be LOWER, because otherwise the class-documentor will use this class for **any**
    # attribute that gets documented via the :members: directive.
    priority = DataDocumenter.priority - 10

    @classmethod
    def can_document_member(cls, member: Any, membername: str, isattr: bool, parent: Any) -> bool:
        return super().can_document_member(member, membername, isattr, parent) and isinstance(member, Mapping)

    def serialize_value(self, value: Any) -> str:
        """Serialize a value (or key) into a string as displayed in the table."""
        if isinstance(value, bool):
            return f"``{value}``"
        if isinstance(value, str):
            return f'``"{value}"``'
        if isinstance(value, x509.ObjectIdentifier):
            # First, try to find out if the OID is an ExtensionOID member
            for name in dir(ExtensionOID):
                # These are currently not documented, see https://github.com/pyca/cryptography/pull/7904
                if value in (ExtensionOID.POLICY_MAPPINGS, ExtensionOID.SUBJECT_DIRECTORY_ATTRIBUTES):
                    return f"``ExtensionOID.{name}``"
                if value == getattr(ExtensionOID, name):
                    return f":py:attr:`ExtensionOID.{name} <cg:cryptography.x509.oid.ExtensionOID.{name}>`"
            return str(value)

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

    def add_content(self, more_content: Optional[StringList]) -> None:
        if more_content is None:
            more_content = StringList()
        more_content += StringList(["A line **appended** by automapping."])
        super().add_content(more_content)

        self.add_table()
