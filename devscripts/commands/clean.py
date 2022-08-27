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

"""The clean subcommand removes all generated files."""

import shutil

from devscripts import config
from devscripts.commands import DevCommand


class Command(DevCommand):  # pylint: disable=missing-class-docstring
    help = "Remove generated files."

    def handle(self, args):
        def rm(path):  # pylint: disable=invalid-name; rm() is just descriptive
            """Remove a file/dir if it exists."""
            rm_path = config.ROOT_DIR / path
            if not rm_path.exists():
                return

            if rm_path.is_dir():
                print("rm -r", rm_path)
                shutil.rmtree(rm_path)
            else:
                print("rm", rm_path)
                rm_path.unlink()

        rm("pip-selfcheck.json")
        rm("geckodriver.log")
        rm("docs/build")
        rm(".tox")
        rm("ca/files")
        rm("ca/geckodriver.log")
        rm("dist")
        rm("build")
        rm(".coverage")
        rm(".docker")
        rm(".mypy_cache")
        rm("contrib/selenium/geckodriver")
        rm("docs/source/_files/docker-compose.yml")

        for path in config.ROOT_DIR.rglob("__pycache__/"):
            shutil.rmtree(path)
        for path in config.ROOT_DIR.rglob("*.pyc"):
            path.unlink()
        for path in config.ROOT_DIR.rglob("*.sqlite3"):
            path.unlink()
        for path in config.ROOT_DIR.rglob("*.egg-info/"):
            shutil.rmtree(path)
