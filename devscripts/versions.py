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

import semantic_version

VersionTuple = tuple[int, int, int] | tuple[int, int, int, str, int]


def get_semantic_version(version: VersionTuple | None = None) -> semantic_version.Version:
    """Get the last django-ca release."""
    if version is None:
        # PYLINT NOTE: import django_ca only here so that it is not imported before coverage tests start
        import django_ca  # pylint: disable=import-outside-toplevel

        version = django_ca.VERSION

    prerelease: tuple[str, ...] | None = None
    if len(version) == 5:
        prerelease = tuple(str(e) for e in version[3:5])
    elif len(version) != 3:
        raise ValueError(f"{version}: django_ca.VERSION must have either three or five elements.")

    return semantic_version.Version(
        major=version[0], minor=version[1], patch=version[2], prerelease=prerelease
    )


def get_last_version() -> semantic_version.Version:
    """Get the last version that was released from ``django_ca.VERSION``."""
    version = get_semantic_version()

    # If this is a development release, just remove prerelease/build and return it
    if version.prerelease or version.build:
        version.prerelease = version.build = None
        return version

    if version.patch > 0:
        version.patch -= 1
        return version
    if version.minor > 0:
        version.minor -= 1
        return version

    # hardcoded branch for 2.0.0:
    if version.minor == 0:
        version.major = 1
        version.minor = 29
        return version
    raise ValueError("Unable to get last release version.")
