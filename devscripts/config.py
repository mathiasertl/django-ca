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

from pathlib import Path
from typing import Any, Dict

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


def get_project_config() -> Dict[str, Any]:
    """Get project configuration from pyproject.toml."""
    # PYLINT NOTE: lazy import so that just importing this module has no external dependencies
    try:
        import tomllib  # pylint: disable=import-outside-toplevel
    except ImportError:  # pragma: py<3.11
        # pylint: disable-next=import-outside-toplevel
        import tomli as tomllib  # type: ignore[no-redef]

    with open(PYPROJECT_PATH, "rb") as stream:
        full_config = tomllib.load(stream)

    cfg: Dict[str, Any] = full_config["django-ca"]["release"]
    cfg["python-map"] = {minor_to_major(pyver): pyver for pyver in cfg["python"]}
    cfg["python-major"] = [minor_to_major(pyver) for pyver in cfg["python"]]

    cfg["docker"] = full_config["django-ca"].setdefault("docker", {})
    _alpine_images = cfg["docker"].setdefault("alpine-images", [])
    if "default" not in _alpine_images:
        _alpine_images.append("default")

    cfg["docker"]["metavar"] = "default|python:{%s-%s}-alpine{%s-%s}" % (
        cfg["python-major"][0],
        cfg["python-major"][-1],
        cfg["alpine"][0],
        cfg["alpine"][-1],
    )
    for pyver in reversed(cfg["python-major"]):
        for alpver in reversed(cfg["alpine"]):
            image_name = f"python:{pyver}-alpine{alpver}"

            # Skip images that are just no longer built upstream
            if image_name in cfg["docker-image-blacklist"]:
                continue

            if image_name not in _alpine_images:
                _alpine_images.append(image_name)

    return cfg
