#!/usr/bin/env python3
#
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

"""Script that removes any files generated files (similar to a traditional "make clean")."""

import argparse
import os
import shutil
from pathlib import Path


def remove(path: Path, dry: bool) -> None:
    """Remove a file/dir if it exists."""
    if not path.exists():
        return

    if path.is_dir():
        print("rm -r", path)
        if not dry:
            shutil.rmtree(path)
    else:
        print("rm", path)
        if not dry:
            path.unlink()


def cleanup(root: Path, dry: bool = False) -> None:
    """Main cleanup function."""
    remove(root / "pip-selfcheck.json", dry=dry)
    remove(root / "geckodriver.log", dry=dry)
    remove(root / "docs/build", dry=dry)
    remove(root / ".tox", dry=dry)
    remove(root / "ca/files", dry=dry)
    remove(root / "ca/geckodriver.log", dry=dry)
    remove(root / "dist", dry=dry)
    remove(root / "build", dry=dry)
    remove(root / ".coverage", dry=dry)
    remove(root / ".docker", dry=dry)
    remove(root / ".idea", dry=dry)
    remove(root / ".mypy_cache", dry=dry)
    remove(root / ".pytest_cache", dry=dry)
    remove(root / ".ruff_cache", dry=dry)
    remove(root / "contrib/selenium/geckodriver", dry=dry)
    remove(root / "docs/source/_files/docker-compose.yml", dry=dry)
    for path in root.glob("*.crl"):
        remove(path, dry=dry)
    for path in root.glob("*.pem"):
        remove(path, dry=dry)
    for path in root.rglob("__pycache__/"):
        remove(path, dry=dry)
    for path in root.rglob("*.pyc"):
        remove(path, dry=dry)
    for path in root.rglob("*.sqlite3"):
        remove(path, dry=dry)
    for path in root.rglob("*.egg-info/"):
        remove(path, dry=dry)


if __name__ == "__main__":
    default_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    parser = argparse.ArgumentParser(description="Remove generated files.")
    parser.add_argument(
        "--dry",
        action="store_true",
        default=False,
        help="Output files that would be removed, don't actually remove them.",
    )
    parser.add_argument("-p", "--path", default=default_root, help="Path to clean (default: %(default)s.")
    args = parser.parse_args()
    cleanup(Path(args.path), dry=args.dry)
