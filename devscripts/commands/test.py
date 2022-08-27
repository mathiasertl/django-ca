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

"""The code-quality subcommand invokes fast linters and manage.py check commands.

This command does **not** invoke pylint (too slow) or mypy.
"""

import os
import sys
import warnings

import pkg_resources

from devscripts import config
from devscripts.commands import DevCommand


class Command(DevCommand):
    """Run the test suite."""

    def add_arguments(self, parser):
        parser.add_argument(
            "--fail-fast", default=False, action="store_true", help="Stop running after first error."
        )
        parser.add_argument("suites", nargs="*", help="Modules to test.", default=["django_ca.tests"])
        parser.add_argument(
            "--no-shuffle",
            dest="shuffle",
            default=True,
            action="store_false",
            help="Do not shuffle test case order.",
        )

        selenium_grp = parser.add_argument_group("Selenium tests")
        selenium_grp.add_argument(
            "--no-selenium",
            dest="selenium",
            action="store_false",
            default=True,
            help="Do not run selenium tests at all.",
        )
        selenium_grp.add_argument(
            "-p",
            "--no-virtual-display",
            dest="virtual_display",
            action="store_false",
            default=True,
            help="Do not run tests in virtual display.",
        )

    def handle(self, args):
        if not args.selenium:
            os.environ["SKIP_SELENIUM_TESTS"] = "y"

        self.setup_django()

        import django  # pylint: disable=import-outside-toplevel
        from django.core.management import call_command  # pylint: disable=import-outside-toplevel

        # Testing the sphinx extension needs documentation in the Python path
        sys.path.insert(0, str(config.DOCS_DIR / "source"))

        # pylint: enable=import-outside-toplevel

        if not args.virtual_display:
            os.environ["VIRTUAL_DISPLAY"] = "n"

        # Set up warnings
        warnings.filterwarnings(action="always")  # print all warnings
        if sys.version_info[:2] >= (3, 10) and django.VERSION[:2] < (4, 0):  # pragma: only django<=4.0
            # This warning only occurs in Python 3.10 and is fixed in Django 4.0:
            #   https://github.com/django/django/commit/623c8cd8f41a99f22d39b264f7eaf7244417000b
            warnings.filterwarnings(
                action="ignore",
                message="There is no current event loop",
                category=DeprecationWarning,
                module="django.utils.asyncio",
            )

        # Can be removed with requests_toolbelt==2.9.2
        #   https://github.com/requests/toolbelt/issues/331
        warnings.filterwarnings(
            action="ignore",
            message=(
                "'urllib3.contrib.pyopenssl' module is deprecated and will be removed in a "
                "future release of urllib3 2.x. Read more in this issue: "
                "https://github.com/urllib3/urllib3/issues/2680"
            ),
            category=DeprecationWarning,
            module="requests_toolbelt._compat",
        )
        warnings.filterwarnings(action="error", module="django_ca")  # turn our warnings into errors

        print("Testing with:")
        print("* Python: ", sys.version.replace("\n", ""))
        # pylint: disable-next=not-an-iterable  # false positive
        installed_versions = {p.project_name: p.version for p in pkg_resources.working_set}
        for pkg in sorted(["Django", "acme", "cryptography", "celery", "idna", "josepy"]):
            print(f"* {pkg}: {installed_versions[pkg]}")

        kwargs = {}
        if django.VERSION[:2] >= (4, 0):  # pragma: only django<4.0
            # shuffle flag was added in Django 4.0
            kwargs["shuffle"] = args.shuffle

        call_command("test", *args.suites, parallel=True, failfast=args.fail_fast, **kwargs)
