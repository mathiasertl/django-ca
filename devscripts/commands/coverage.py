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

"""A subclass of the test command that enables code coverage analysis."""

import os
import sys

import coverage
import packaging.version

import cryptography

import django

from devscripts import config
from devscripts.commands.test import Command as TestCommand


def exclude_versions(cov, software, current_version, pragma_version, version_str):
    """
    Parameters
    ----------
    sw : str
    current_version
        The currently used version.
    pragma_version
        The version to add pragmas for.
    version_str:
        Same as `version` but as ``str``.
    """

    if current_version == pragma_version:
        cov.exclude(f"pragma: only {software}>{version_str}")
        cov.exclude(f"pragma: only {software}<{version_str}")

        cov.exclude(f"pragma: {software}<{version_str} branch")
        cov.exclude(f"pragma: {software}!={version_str}")

        # branches
        cov.exclude(f"pragma: {software}>={version_str}", which="partial")
        cov.exclude(f"pragma: {software}<={version_str}", which="partial")

        # completely exclude pragma branches that just don't match.
        # For example, when running python 3.9:
        #
        # if sys.version_info[:2] > (3, 9):  # pragma: py>3.9 branch
        #     print("Only python 3.10 or later")
        #
        # --> just completely exclude the block, as it is never executed
        cov.exclude(f"pragma: {software}>{version_str} branch")
        cov.exclude(f"pragma: {software}<{version_str} branch")
    else:
        cov.exclude(f"pragma: only {software}=={version_str}")
        cov.exclude(f"pragma: {software}!={version_str}", which="partial")

        if current_version < pragma_version:
            cov.exclude(f"pragma: only {software}>={version_str}")
            cov.exclude(f"pragma: only {software}>{version_str}")

            # Branches that run in the current version
            cov.exclude(f"pragma: {software}<{version_str} branch", which="partial")
            cov.exclude(f"pragma: {software}<={version_str} branch", which="partial")

            # Completely exclude branches only used in *newer* versions. For example, if you use Python 3.8:
            #
            # if sys.version_info[:2] > (3, 9):  # pragma: py>3.9 branch
            #     print("Only python 3.9 or later")
            #
            # --> The branch is never executed on Python 3.8.
            cov.exclude(f"pragma: {software}>{version_str} branch")
            cov.exclude(f"pragma: {software}>={version_str} branch")

        if current_version > pragma_version:
            cov.exclude(f"pragma: only {software}<={version_str}")
            cov.exclude(f"pragma: only {software}<{version_str}")

            # Branches that run in the current version
            cov.exclude(f"pragma: {software}>{version_str} branch", which="partial")
            cov.exclude(f"pragma: {software}>={version_str} branch", which="partial")

            # Completely exclude branches only used in *older* versions. For example, if you use Python 3.9:
            #
            # if sys.version_info[:2] < (3, 9):  # pragma: py<3.9 branch
            #     print("Only before Python 3.9")
            #
            # --> The branch is never executed on Python 3.9.
            cov.exclude(f"pragma: {software}<{version_str} branch")
            cov.exclude(f"pragma: {software}<={version_str} branch")


class Command(TestCommand):  # pylint: disable=missing-class-docstring
    help = "Run the test suite with coverage analysis enabled."

    def add_arguments(self, parser):
        super().add_arguments(parser)

        parser.add_argument(
            "-f",
            "--format",
            choices=["html", "text"],
            default="html",
            help="Write coverage report as text (default: %(default)s).",
        )
        parser.add_argument(
            "--fail-under",
            type=int,
            default=100,
            metavar="[0-100]",
            help="Fail if coverage is below given percentage (default: %(default)s%%).",
        )

    def setup_pragmas(self, cov):
        """Setup pragmas to allow coverage exclusion based on Python/django/cryptography version."""

        # exclude python version specific code
        py_versions = [(3, 5), (3, 6), (3, 7), (3, 8), (3, 9), (3, 10), (3, 11)]
        for version in py_versions:
            version_str = ".".join([str(v) for v in version])
            exclude_versions(cov, "py", sys.version_info[:2], version, version_str)

        # exclude django-version specific code
        django_versions = [(2, 2), (3, 0), (3, 1), (4, 0), (4, 1), (4, 2)]
        for version in django_versions:
            version_str = ".".join([str(v) for v in version])
            exclude_versions(cov, "django", django.VERSION[:2], version, version_str)

        # exclude cryptography-version specific code
        this_version = packaging.version.parse(cryptography.__version__).release[:2]
        cryptography_versions = [(3, 3), (3, 4), (35, 0), (36, 0), (37, 0), (38, 0), (39, 0)]
        for ver in cryptography_versions:
            version_str = ".".join([str(v) for v in ver])
            exclude_versions(cov, "cryptography", this_version, ver, version_str)

    def handle(self, args):
        if "TOX_ENV_DIR" in os.environ:  # was invoked via tox
            # Write coverage into .tox/{env}/coverage
            report_dir = os.path.join(os.environ["TOX_ENV_DIR"], "coverage")
            # Use a dedicated data file to enable parallel tox runs
            data_file = os.path.join(os.environ["TOX_ENV_DIR"], ".coverage")
        else:
            report_dir = str(config.DOCS_BUILD_DIR / "coverage")
            data_file = None

        cov = coverage.Coverage(
            data_file=data_file,
            cover_pylib=False,
            branch=True,
            source=["django_ca"],
            omit=[
                "*migrations/*",
                "*/tests/tests*",
            ],
        )

        self.setup_pragmas(cov)
        cov.start()

        super().handle(args)

        cov.stop()
        cov.save()

        if args.format == "text":
            total_coverage = cov.report()
        else:
            total_coverage = cov.html_report(directory=report_dir)

        if total_coverage < args.fail_under:
            if args.fail_under == 100.0:
                print(f"Error: Coverage was only {total_coverage:.2f}% (should be 100%).")
            else:
                print(f"Error: Coverage was only {total_coverage:.2f}% (should be above {args.fail_under}%).")
            sys.exit(2)  # coverage cli utility also exits with 2
