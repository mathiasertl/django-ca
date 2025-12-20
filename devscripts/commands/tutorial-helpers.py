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
import json
import re
import subprocess
import types
from typing import Any

import requests

from devscripts import config, utils
from devscripts.commands import DevCommand
from devscripts.out import err, ok


class Command(DevCommand):
    """Class implementing the ``dev.py release`` command."""

    help_text = "Helper commands for structured-tutorials."

    modules = (("django_ca", "django-ca"),)
    django_ca: types.ModuleType
    _compose_services = ("beat", "backend", "frontend")

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        subparsers = parser.add_subparsers(dest="subcommand")
        subparsers.add_parser("get-release", help="Just print the current version and exit.")
        subparsers.add_parser(  # full image name
            "get-docker-tag",
            help="Just print the Docker tag based on the current version and exit.",
        )
        subparsers.add_parser(  # just the version of the image
            "get-docker-version",
            help="Just print the Docker version based on the current version and exit.",
        )
        docker_compose_parser = subparsers.add_parser(  # just the version of the image
            "compose",
            help="Helpers for the compose tutorial.",
        )
        docker_compose_action_parser = docker_compose_parser.add_subparsers(dest="action", required=True)
        compose_status_parser = docker_compose_action_parser.add_parser("test-compose-status")
        compose_status_parser.add_argument("tag")
        container_versions_parser = docker_compose_action_parser.add_parser("test-container-versions")
        container_versions_parser.add_argument("release")
        docker_compose_action_parser.add_parser("test-secret-keys")
        docker_compose_action_parser.add_parser("test-connectivity")
        endpoints_parser = docker_compose_action_parser.add_parser("test-endpoints")
        endpoints_parser.add_argument("verify", help="Path to SSL certificate for SSL verification.")

    def _compose(self, *args: str, **kwargs: Any) -> subprocess.CompletedProcess[Any]:
        kwargs.setdefault("text", True)
        return utils.run(["docker", "compose", *args], **kwargs)

    def _compose_exec(self, container: str, *args: str, **kwargs: Any) -> subprocess.CompletedProcess[Any]:
        return self._compose("exec", *kwargs.pop("compose_args", []), container, *args, **kwargs)

    def _compose_manage(self, container: str, *args: str, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return self._compose_exec(container, "manage", *args, **kwargs)

    def _compose_python(self, container: str, code: str, **kwargs) -> subprocess.CompletedProcess[str]:
        return self._compose_manage(container, "shell", "-v", "0", "-c", code, capture_output=True)

    def test_compose_status(self, tag: str) -> int:
        proc = self._compose("ps", "-a", "--format=json", capture_output=True)
        json_lines = proc.stdout.splitlines()
        if not json_lines:
            return err("No containers found.")

        errors = 0
        services = {}
        for line in json_lines:
            container_data = json.loads(line)
            if (exit_code := container_data["ExitCode"]) != 0:
                errors += err(f"{container_data['Service']}: Exit code {exit_code}")

            if container_data["Service"] in self._compose_services:
                if container_data["Image"] != tag:
                    errors += err(f"{container_data['Service']}: Image {container_data['Image']} != {tag}")

        if not errors:
            ok("All containers have started successfully.")
        return errors

    def test_container_versions(self, release: str) -> int:
        code = "import django_ca; print(django_ca.__version__)"
        errors = 0
        for service in self._compose_services:
            ver = self._compose_python(service, code).stdout.strip()
            if ver != release:
                errors += err(f"backend container identifies as {ver} instead of {release}.")

        if not errors:
            ok(f"All containers identify as {release}.")
        return errors

    def test_secret_keys(self) -> int:
        code = "from django.conf import settings; print(settings.SECRET_KEY)"
        errors = 0
        beat_key = self._compose_python("beat", code).stdout.strip()
        backend_key = self._compose_python("backend", code).stdout.strip()
        frontend_key = self._compose_python("frontend", code).stdout.strip()

        if beat_key != backend_key:
            errors += err(f"Secret key in beat do not match backend: ({frontend_key} vs. {backend_key}")
        if backend_key != frontend_key:
            errors += err(f"Secret keys do not match ({frontend_key} vs. {backend_key}")
        if len(backend_key) < 32 or len(backend_key) > 128:
            errors += err(f"Secret key seems to have an unusual length: {backend_key}")
        if not errors:
            ok("All containers have the same valid secret key.")
        return errors

    def test_connectivity(self) -> int:
        standalone_dir = config.ROOT_DIR / "devscripts" / "standalone"
        standalone_dest = "/usr/src/django-ca/ca/"

        errors = 0
        for service in self._compose_services:
            self._compose("cp", str(standalone_dir / "test-connectivity.py"), f"{service}:{standalone_dest}")
            proc = self._compose_exec(service, "./test-connectivity.py", check=False)
            if proc.returncode != 0:
                errors += 1

        if errors == 0:
            return ok("Tested connectivity.")
        return errors

    def test_endpoints(
        self, base_url: str, api_user: str, api_password: str, verify: str | None = None
    ) -> int:
        # Test that HTTPS connection and admin interface is working:
        resp = requests.get(f"{base_url}/admin/", verify=verify, timeout=10)
        resp.raise_for_status()

        # Test static files
        resp = requests.get(f"{base_url}/static/admin/css/base.css", verify=verify, timeout=10)
        resp.raise_for_status()

        # Test the REST API
        resp = requests.get(f"{base_url}/api/ca/", auth=(api_user, api_password), verify=verify, timeout=10)
        resp.raise_for_status()

        # Test (principal) ACME connection
        resp = requests.get(f"{base_url}/acme/directory/", verify=verify, timeout=10)
        resp.raise_for_status()
        return ok("Endpoints verified.")

    def handle(self, args: argparse.Namespace) -> int:
        if args.subcommand == "get-release":
            print(self.django_ca.__version__)
            return 0
        elif args.subcommand == "get-docker-tag":
            safe_tag = re.sub(r"[^\w.-]", ".", self.django_ca.__version__)
            print(f"{config.DOCKER_TAG}:{safe_tag}")
            return 0
        elif args.subcommand == "get-docker-version":
            print(re.sub(r"[^\w.-]", ".", self.django_ca.__version__))
            return 0
        elif args.subcommand == "compose":
            if args.action == "test-compose-status":
                return self.test_compose_status(args.tag)
            elif args.action == "test-container-versions":
                return self.test_container_versions(args.release)
            elif args.action == "test-secret-keys":
                return self.test_secret_keys()
            elif args.action == "test-connectivity":
                return self.test_connectivity()
            elif args.action == "test-endpoints":
                return self.test_endpoints("https://localhost", "user", "nopass", verify=args.verify)
        return 1
