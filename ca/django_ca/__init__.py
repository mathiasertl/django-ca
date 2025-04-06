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

from importlib.metadata import PackageNotFoundError, version

from packaging.version import Version as PackagingVersion

try:
    __version__ = version("django-ca")

    __packaging_version__ = PackagingVersion(__version__)
    VERSION: tuple[int | str, ...] = __packaging_version__.release
    if __packaging_version__.dev:  # pragma: no cover
        VERSION = (*VERSION, "dev", __packaging_version__.dev)
    if __packaging_version__.pre:  # pragma: no cover
        VERSION = (*VERSION, "pre", *__packaging_version__.pre)
    if __packaging_version__.post:  # pragma: no cover
        VERSION = (*VERSION, "post", __packaging_version__.post)
    if __packaging_version__.local:  # pragma: no cover
        VERSION = (*VERSION, __packaging_version__.local)
except PackageNotFoundError:  # pragma: no cover  # package is not installed
    pass
