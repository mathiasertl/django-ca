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

"""Command for various helper scripts for tutorials."""

import argparse
import re
import types
from typing import TYPE_CHECKING

from devscripts import config
from devscripts.commands import DevCommand
from devscripts.docker import (
    compose_python,
    compose_status,
    compose_test_connectivity,
    compose_validate_container_versions,
    test_connectivity,
)
from devscripts.out import err, ok
from devscripts.utils import test_endpoints

if TYPE_CHECKING:
    SubParser = argparse._SubParsersAction[argparse.ArgumentParser]  # pylint: disable=protected-access
else:
    SubParser = argparse._SubParsersAction  # pylint: disable=protected-access


class Command(DevCommand):
    """Class implementing the ``dev.py release`` command."""

    help_text = "Helper commands for structured-tutorials."

    modules = (("django_ca", "django-ca"),)
    django_ca: types.ModuleType

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        subparsers = parser.add_subparsers(dest="subcommand")
        subparsers.add_parser("get-release", help="Just print the current version and exit.")
        docker_tag_parser = subparsers.add_parser(  # full image name
            "get-docker-tag",
            help="Just print the Docker tag based on the current version and exit.",
        )
        docker_tag_parser.add_argument("--variant", choices=("debian", "alpine"), default="debian")
        subparsers.add_parser(  # just the version of the image
            "get-docker-version",
            help="Just print the Docker version based on the current version and exit.",
        )
        self.add_docker_arguments(subparsers)
        self.add_compose_arguments(subparsers)

    def add_docker_arguments(self, subparsers: SubParser) -> None:
        """Add arguments for the Docker action."""
        parser = subparsers.add_parser("docker", help="Helpers for the Docker tutorial.")
        action_parser = parser.add_subparsers(dest="action", required=True)
        action_parser.add_parser("test-connectivity")

    def add_compose_arguments(self, subparsers: SubParser) -> None:
        """Add arguments for the Compose action."""
        parser = subparsers.add_parser("compose", help="Helpers for the Compose tutorial.")
        action_parser = parser.add_subparsers(dest="action", required=True)
        compose_status_parser = action_parser.add_parser("test-compose-status")
        compose_status_parser.add_argument("tag")
        container_versions_parser = action_parser.add_parser("test-container-versions")
        container_versions_parser.add_argument("release")
        action_parser.add_parser("test-secret-keys")
        action_parser.add_parser("test-connectivity")
        endpoints_parser = action_parser.add_parser("test-endpoints")
        endpoints_parser.add_argument("verify", help="Path to SSL certificate for SSL verification.")

    def test_secret_keys(self) -> int:
        """Test that secret keys match and have reasonable values."""
        code = "from django.conf import settings; print(settings.SECRET_KEY)"
        errors = 0
        beat_key = compose_python("beat", code).stdout.strip()
        backend_key = compose_python("backend", code).stdout.strip()
        frontend_key = compose_python("frontend", code).stdout.strip()

        if beat_key != backend_key:
            errors += err(f"Secret key in beat do not match backend: ({frontend_key} vs. {backend_key}")
        if backend_key != frontend_key:
            errors += err(f"Secret keys do not match ({frontend_key} vs. {backend_key}")
        if len(backend_key) < 32 or len(backend_key) > 128:
            errors += err(f"Secret key seems to have an unusual length: {backend_key}")
        if not errors:
            ok("All containers have the same valid secret key.")
        return errors

    def handle(self, args: argparse.Namespace) -> int:
        if args.subcommand == "get-release":
            print(self.django_ca.__version__)
        elif args.subcommand == "get-docker-tag":
            safe_tag = re.sub(r"[^\w.-]", ".", self.django_ca.__version__)
            if args.variant == "alpine":
                safe_tag += "-alpine"
            print(f"{config.DOCKER_TAG}:{safe_tag}")
        elif args.subcommand == "get-docker-version":
            print(re.sub(r"[^\w.-]", ".", self.django_ca.__version__))
        elif args.subcommand == "docker":
            if args.subcommand == "test-connectivity":
                return test_connectivity()
        elif args.subcommand == "compose":
            if args.action == "test-compose-status":
                return compose_status(args.tag)
            if args.action == "test-container-versions":
                return compose_validate_container_versions(args.release)
            if args.action == "test-secret-keys":
                return self.test_secret_keys()
            if args.action == "test-connectivity":
                return compose_test_connectivity()
            if args.action == "test-endpoints":
                return test_endpoints("https://webserver", "user", "nopass", verify=args.verify)
        else:
            return err("Unknown subcommand.")
        return 0
