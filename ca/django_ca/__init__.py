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

"""django-ca root module."""

from typing import Any, Union

VersionTuple = Union[tuple[int, int, int], tuple[int, int, int, str, int]]

# WARNING: This module MUST NOT include any dependencies, as it is read by setup.py

# Between releases: (Major, Minor, Patch, "dev", 1)
# On a release: (Major, Minor, Patch)
# https://www.python.org/dev/peps/pep-0440/
# https://www.python.org/dev/peps/pep-0396/
# https://www.python.org/dev/peps/pep-0386/
VERSION: VersionTuple = (2, 0, 0)

# __version__ specified in PEP 0396, but we use the PEP 0440 format instead
__version__ = ".".join([str(e) for e in VERSION[:3]])
if len(VERSION) > 3:  # pragma: no cover
    # NOTE: dev_elements hack here only to make mypy happy in both dev and non-dev versions
    dev_elements: tuple[Any, ...] = VERSION[3:5]
    __version__ += f".{''.join(str(e) for e in dev_elements)}"
