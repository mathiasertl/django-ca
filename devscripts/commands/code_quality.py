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

# pylint: disable=missing-module-docstring  # covered in class docstring


from devscripts import config
from devscripts.commands import DevCommand


class Command(DevCommand):
    """Run linters and manage.py check commands.

    This command does **not** invoke pylint (too slow) or mypy.
    """

    def manage(self, *args):
        """Shortcut to run manage.py with warnings turned into errors."""
        python = ["python", "-Wd"]

        # Django 4.0 changes the default to True. Remove USE_L10N setting once support for Django<4.0 is
        # dropped.
        #   https://docs.djangoproject.com/en/4.0/releases/4.0/#miscellaneous
        python += ["-W", "ignore:The USE_L10N setting is deprecated."]  # pragma: only django<4.0

        # urllib3==1.26.12 deprecates urllib3.contrib.pyopenssl and is used by requests-toolbelt=0.9.1
        #   https://github.com/requests/toolbelt/issues/331
        python += ["-W", "ignore:'urllib3.contrib.pyopenssl' module is deprecated and will be removed"]

        python.append(config.MANAGE_PY.relative_to(config.ROOT_DIR))
        python += args
        return self.run(*python)

    def handle(self, args):
        self.run("isort", "--check-only", "--diff", ".")
        self.run("flake8", ".")
        self.run("black", "--check", ".")
        self.run("pre-commit", "run", "--all-files")

        self.manage("check")
        self.manage("makemigrations", "--check")
