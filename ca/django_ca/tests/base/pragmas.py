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

"""Module demonstrating and testing the use of coverage pragmas.

.. seealso:: https://django-ca.readthedocs.io/en/latest/standards.html
"""

import sys

VERSION = sys.version_info[:2]  # e.g. ``(3, 8)`` or ``(3, 9)``


# PYLINT NOTE: pragma argument so we can optionally add a print() for testing
def noop(pragma: str) -> None:  # pylint: disable=unused-argument
    """Dummy function called in branches to make sure that coverage detects executed LOCs."""


# NOTE: You can also use "django" or "cryptography" as software version
if VERSION > (3, 11):  # pragma: only py>3.11
    noop("py>3.11")
else:  # pragma: only py<=3.11
    noop("py<=3.11")

if VERSION >= (3, 11):  # pragma: only py>=3.11
    noop("py>=3.11")
else:  # pragma: only py<3.11
    noop("py<3.11")

if VERSION == (3, 11):  # pragma: only py==3.11
    noop("py==3.11")
else:  # pragma: py!=3.11
    noop("py!=3.11")

if VERSION <= (3, 11):  # pragma: only py<=3.11
    noop("py<=3.11")
else:  # pragma: only py>3.11
    noop("py>3.11")

if VERSION < (3, 11):  # pragma: only py<3.11
    noop("py<3.11")
else:  # pragma: only py>=3.11
    noop("py>=3.11")


# Test previous version
if VERSION > (3, 11):  # pragma: py>3.11 branch
    noop("py>3.11 branch")

if VERSION >= (3, 11):  # pragma: py>=3.11 branch
    noop("py>=3.11 branch")

if VERSION == (3, 11):  # pragma: only py==3.11
    noop("py==3.11 branch")

if VERSION != (3, 11):  # pragma: py!=3.11
    noop("py!=3.11 branch")

if VERSION <= (3, 11):  # pragma: py<=3.11 branch
    noop("py<=3.11 branch")

if VERSION < (3, 11):  # pragma: py<3.11 branch
    noop("py<=3.11 branch")

# Test current version
if VERSION > (3, 12):  # pragma: py>3.12 branch
    noop("py>3.12 branch")

if VERSION >= (3, 12):  # pragma: py>=3.12 branch
    noop("py>=3.12 branch")

if VERSION == (3, 12):  # pragma: only py==3.12
    noop("py==3.12 branch")

if VERSION != (3, 12):  # pragma: py!=3.12
    noop("py!=3.12 branch")

if VERSION <= (3, 12):  # pragma: py<=3.12 branch
    noop("py<=3.12 branch")

if VERSION < (3, 12):  # pragma: py<3.12 branch
    noop("py<=3.12 branch")

# Test next version
if VERSION > (3, 10):  # pragma: py>3.10 branch
    noop("py>3.10 branch")

if VERSION >= (3, 10):  # pragma: py>=3.10 branch
    noop("py>=3.10 branch")

if VERSION == (3, 10):  # pragma: only py==3.10
    noop("py==3.10 branch")

if VERSION != (3, 10):  # pragma: py!=3.10
    noop("py!=3.10 branch")

if VERSION <= (3, 10):  # pragma: py<=3.10 branch
    noop("py<=3.10 branch")

if VERSION < (3, 10):  # pragma: py<3.10 branch
    noop("py<=3.10 branch")
