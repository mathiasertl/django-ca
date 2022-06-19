# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca. If not,
# see <http://www.gnu.org/licenses/>.

"""Module to parse ``pyproject.toml`` and augment with auto-generated values."""

import os
from pathlib import Path

import semantic_version
import toml


def minor_to_major(version):
    """Convert minor to major version."""
    if version.count(".") == 1:
        return version
    return ".".join(version.split(".", 2)[:2])


def get_release_tags(repo):
    """Get all git tags that are a semantic version."""
    for tag in repo.tags:
        try:
            ver = semantic_version.Version(tag.name)
        except ValueError:  # not a semantic version
            continue

        if ver.prerelease or ver.build:
            continue

        yield (ver, tag)


def get_last_release():
    """Function to get the last git release."""
    # Lazy import because git is not installed in some environments (e.g. tests in Docker)
    import git

    repo = git.Repo(ROOT_DIR)
    prev_tag, last_tag = sorted(get_release_tags(repo))[-2:]

    # if the current head is a tag (= this is a release commit), return the tag before that
    if repo.head.commit == last_tag[1].commit:
        return prev_tag[1]

    # ... otherwise just return the last tag
    return last_tag[1]


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(os.path.dirname(BASE_DIR))
PYPROJECT_PATH = os.path.join(ROOT_DIR, "pyproject.toml")
DOCS_DIR = Path(ROOT_DIR) / "docs"
DOC_TEMPLATES_DIR = DOCS_DIR / "source" / "include"
SRC_DIR = Path(ROOT_DIR) / "ca"

with open(PYPROJECT_PATH, encoding="utf-8") as stream:
    FULL_CONFIG = toml.load(stream)

CONFIG = FULL_CONFIG["django-ca"]["release"]
CONFIG["python-map"] = {minor_to_major(pyver): pyver for pyver in CONFIG["python"]}
CONFIG["python-major"] = [minor_to_major(pyver) for pyver in CONFIG["python"]]
CONFIG["django-map"] = {minor_to_major(djver): djver for djver in CONFIG["django"]}
CONFIG["django-major"] = [minor_to_major(djver) for djver in CONFIG["django"]]
CONFIG["cryptography-map"] = {minor_to_major(cgver): cgver for cgver in CONFIG["cryptography"]}
CONFIG["cryptography-major"] = [minor_to_major(cgver) for cgver in CONFIG["cryptography"]]
CONFIG["acme-map"] = {minor_to_major(acmever): acmever for acmever in CONFIG["acme"]}
CONFIG["acme-major"] = [minor_to_major(acmever) for acmever in CONFIG["acme"]]
CONFIG["josepy-map"] = {minor_to_major(josepyver): josepyver for josepyver in CONFIG["josepy"]}
CONFIG["josepy-major"] = [minor_to_major(josepyver) for josepyver in CONFIG["josepy"]]

DOCKER_TAG = "mathiasertl/django-ca"
DOCKER_CONFIG = FULL_CONFIG["django-ca"].setdefault("docker", {})
_alpine_images = DOCKER_CONFIG.setdefault("alpine-images", [])
if "default" not in _alpine_images:
    _alpine_images.append("default")

DOCKER_CONFIG[
    "metavar"
] = "default|python:{%s-%s}-alpine{%s-%s}" % (  # pylint: disable=consider-using-f-string
    CONFIG["python-major"][0],
    CONFIG["python-major"][-1],
    CONFIG["alpine"][0],
    CONFIG["alpine"][-1],
)
for pyver in reversed(CONFIG["python-major"]):
    for alpver in reversed(CONFIG["alpine"]):
        # Skip images that are just no longer built upstream
        if (pyver, alpver) in [("3.10", "3.12")]:
            continue

        if f"python:{pyver}-alpine{alpver}" not in _alpine_images:
            _alpine_images.append(f"python:{pyver}-alpine{alpver}")
