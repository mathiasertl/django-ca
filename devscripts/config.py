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

import os
from pathlib import Path
from typing import Any, Dict

from django.utils.functional import LazyObject, empty


def minor_to_major(version: str) -> str:
    """Convert minor to major version."""
    if version.count(".") == 1:
        return version
    return ".".join(version.split(".", 2)[:2])


class WrappedConfig:
    def __init__(self, path: "os.PathLike[str]") -> None:
        # PYLINT NOTE: lazy import so that just importing this module has no external dependencies
        try:
            import tomllib  # pylint: disable=import-outside-toplevel
        except ImportError:  # pragma: py<3.11
            # pylint: disable-next=import-outside-toplevel
            import tomli as tomllib  # type: ignore[no-redef]

        with open(path, "rb") as stream:
            full_config = tomllib.load(stream)

        cfg: Dict[str, Any] = full_config["django-ca"]["release"]
        self.PYTHON_MAP = {minor_to_major(pyver): pyver for pyver in cfg["python"]}
        self.PYTHON_MAJOR = [minor_to_major(pyver) for pyver in cfg["python"]]
        self.DJANGO = tuple(cfg["django"])
        self.CRYPTOGRAPHY = tuple(cfg["cryptography"])
        self.ACME = tuple(cfg["acme"])

        self.ALPINE_RELEASES = tuple(cfg["alpine"])
        self.DEBIAN_RELEASES = tuple(cfg["debian-releases"])
        self.UBUNTU_RELEASES = tuple(cfg["ubuntu-releases"])

        # Compute list of valid alpine images
        alpine_images = ["default"]
        for python_version in reversed(self.PYTHON_MAJOR):
            for alpine_version in reversed(self.ALPINE_RELEASES):
                image_name = f"python:{python_version}-alpine{alpine_version}"

                # Skip images that are just no longer built upstream
                if image_name in cfg["docker-image-blacklist"]:
                    continue

                alpine_images.append(image_name)
        self.ALPINE_IMAGES = tuple(alpine_images)

    def __getattr__(self, name: str) -> Any:
        if name.isupper():
            try:
                return globals()[name]
            except KeyError as ex:
                raise AttributeError(f"{name}: Unknown (global) setting") from ex
        raise AttributeError(f"{name}: Settings must be upper case")


class LazyConfig(LazyObject):
    _wrapped = None

    # Settings that can be computed at module load time
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

    def _setup(self, path: "os.PathLike[str]") -> None:
        self._wrapped = WrappedConfig(path)

    def __getattr__(self, name: str) -> Any:
        if (_wrapped := self._wrapped) is empty:
            self._setup(self.PYPROJECT_PATH)
            _wrapped = self._wrapped
        val = getattr(_wrapped, name)

        self.__dict__[name] = val
        return val


config = LazyConfig()
