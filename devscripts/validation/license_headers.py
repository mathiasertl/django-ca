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

"""validation module to validate license headers."""
import argparse
import difflib
import os
import textwrap
from pathlib import Path
from typing import Union

from devscripts.commands import CommandError, DevCommand

try:
    import tomllib
except ImportError:  # pragma: py<3.11
    import tomli as tomllib  # type: ignore[no-redef]

LICENSE_HEADER = """This file is part of django-ca (https://github.com/mathiasertl/django-ca).

django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU General
Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
for more details.

You should have received a copy of the GNU General Public License along with django-ca. If not, see
<http://www.gnu.org/licenses/>."""

PYTHON_BIN_HEADER = """#!/usr/bin/env python3
#
"""

PYTHON_LICENSE_HEADER = textwrap.indent(LICENSE_HEADER, "# ").replace("\n\n", "\n#\n")
PYTHON_READ_LENGTH = len(PYTHON_BIN_HEADER) + len(LICENSE_HEADER) + 64


def handle_python_file(path: Union[str, "os.PathLike[str]"], script: bool) -> int:
    """Check the license header for a Python file."""
    expected_header = PYTHON_LICENSE_HEADER
    if script is True:
        expected_header = PYTHON_BIN_HEADER + PYTHON_LICENSE_HEADER

    with open(path, encoding="utf-8") as stream:
        actual_header = stream.read(PYTHON_READ_LENGTH)

        # skip empty files
        if not actual_header:
            return 0

        if not actual_header.startswith(expected_header):
            actual_lines = actual_header.splitlines()
            expected_lines = expected_header.splitlines()

            diff = difflib.unified_diff(
                actual_lines, expected_lines, fromfile=str(path) + ".orig", tofile=str(path), lineterm=""
            )
            print("\n".join(diff))
            return 1
    return 0


class Command(DevCommand):
    help_text = "Ensure consistent license headers in source files."

    def handle(self, args: argparse.Namespace) -> None:
        """Main validation function."""
        errors = 0
        with open("pyproject.toml", "rb") as stream:
            config = tomllib.load(stream)

        standalone_scripts = config["django-ca"]["validation"]["standalone-scripts"]
        excludes = config["django-ca"]["validation"]["excludes"]

        for directory in ["ca", "docs/source", "devscripts"]:
            for path in sorted(Path(directory).glob("**/*.py")):
                if not any(path.match(exclude) for exclude in excludes):
                    errors += handle_python_file(path, script=str(path) in standalone_scripts)

        if errors != 0:
            raise CommandError(f"{errors} inconsistent license headers found.")
