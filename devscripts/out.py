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

"""Various utility functions for output."""

from termcolor import colored


def bold(msg: str) -> str:
    """Return the text as bold text."""
    return colored(msg, attrs=["bold"])


def err(msg: str) -> int:
    """Print the error message."""
    print(colored("[ERR]", "red", attrs=["bold"]), msg)
    return 1


def info(msg: str, indent: str = "") -> int:
    """Print warning message."""
    print(colored(f"{indent}[INFO]", "magenta"), msg)
    return 0


def warn(msg: str) -> int:
    """Print warning message."""
    print(colored("[WARN]", "yellow", attrs=["bold"]), msg)
    return 0


def ok(msg: str) -> int:
    """Print success message."""
    print(colored("[OKAY]", "green"), msg)
    return 0


def disabled(msg: str, indent: str = "") -> int:
    """Print a message that is temporarily disabled."""
    print(colored(f"{indent}[DISABLED]", "magenta"), msg)
    return 0
