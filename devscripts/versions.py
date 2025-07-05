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

"""Module to parse ``pyproject.toml`` and augment with auto-generated values."""


def get_last_version() -> str:
    """Get the last version that was released based on the installed versiond."""
    import django_ca  # noqa: PLC0415

    version = django_ca.__packaging_version__

    major, minor, patch = version.release
    if version.is_prerelease or version.is_devrelease:
        if patch != 0:
            patch -= 1
        elif minor != 0:
            minor -= 1
        else:
            major -= 1

    return ".".join(str(e) for e in (major, minor, patch))
