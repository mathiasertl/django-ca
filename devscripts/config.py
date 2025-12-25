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

"""Collection of directories and constants."""

import typing
from pathlib import Path

try:
    import tomllib
except ImportError:  # pragma: py<3.11  # tomllib was added in Python 3.11
    import tomli as tomllib  # type: ignore[no-redef]


BASE_DIR = Path(__file__).resolve()
ROOT_DIR = Path(BASE_DIR).parent.parent
PYPROJECT_PATH = ROOT_DIR / "pyproject.toml"
DOCS_DIR = Path(ROOT_DIR) / "docs"
DOCS_BUILD_DIR = DOCS_DIR / "build"
DOCS_SOURCE_DIR = DOCS_DIR / "source"
DOC_TEMPLATES_DIR = DOCS_SOURCE_DIR / "include"
SRC_DIR = ROOT_DIR / "ca"
MANAGE_PY = SRC_DIR / "manage.py"
FIXTURES_DIR = SRC_DIR / "django_ca" / "tests" / "fixtures"
DOCKER_TAG = "mathiasertl/django-ca"
DEVSCRIPTS_DIR = ROOT_DIR / "devscripts"
DEVSCRIPTS_FILES = DEVSCRIPTS_DIR / "files"

SHOW_COMMANDS = False
SHOW_COMMAND_OUTPUT = False


def minor_to_major(version: str) -> str:
    """Convert minor to major version."""
    if version.count(".") == 1:
        return version
    return ".".join(version.split(".", 2)[:2])


with open(PYPROJECT_PATH, "rb") as _pyproject_stream:
    PYPROJECT_TOML = tomllib.load(_pyproject_stream)
RELEASE = PYPROJECT_TOML["django-ca"]["release"]

EXTRAS = PYPROJECT_TOML["project"]["optional-dependencies"]
PYTHON_RELEASES = tuple(typing.cast(list[str], sorted(RELEASE["python"])))
DJANGO = tuple(typing.cast(list[str], RELEASE["django"]))
CRYPTOGRAPHY = tuple(typing.cast(list[str], RELEASE["cryptography"]))
ACME = tuple(typing.cast(list[str], RELEASE["acme"]))
PYDANTIC = tuple(typing.cast(list[str], RELEASE["pydantic"]))

UV: str = RELEASE["uv"]
NEWEST_PYTHON = PYTHON_RELEASES[-1]

ALPINE_RELEASES = tuple(typing.cast(list[str], RELEASE["alpine"]))
DEBIAN_RELEASES = tuple(typing.cast(list[str], RELEASE["debian-releases"]))
UBUNTU_RELEASES = tuple(typing.cast(list[str], RELEASE["ubuntu-releases"]))
GITHUB_CONFIG = RELEASE["github"]
