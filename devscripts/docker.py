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

"""Module collecting some shared docker functionality."""

import json
import subprocess
from typing import Any

from devscripts import config, utils
from devscripts.out import err, ok
from devscripts.utils import run

COMPOSE_SERVICES = ("beat", "backend", "frontend")


def docker_run(*args: str, **kwargs: Any) -> "subprocess.CompletedProcess[Any]":
    """Shortcut for running a docker command."""
    return run(["docker", "run", "--rm", *args], **kwargs)


def docker_exec(container: str, *args: str) -> "subprocess.CompletedProcess[Any]":
    """Run a command in the given Docker container."""
    return run(["docker", "exec", container, *args])


def docker_cp(src: str, container: str, dest: str) -> None:
    """Copy file into the container."""
    utils.run(["docker", "cp", src, f"{container}:{dest}"])


def compose(*args: str, **kwargs: Any) -> subprocess.CompletedProcess[str]:
    """Run docker compose."""
    kwargs["text"] = True
    return utils.run(["docker", "compose", *args], **kwargs)


def compose_exec(container: str, *args: str, **kwargs: Any) -> subprocess.CompletedProcess[str]:
    """Run docker compose exec."""
    return compose("exec", *kwargs.pop("compose_args", []), container, *args, **kwargs)


def compose_cp(src: str, dest: str) -> subprocess.CompletedProcess[str]:
    """Copy file into the container."""
    return compose("cp", src, dest)


def compose_manage(container: str, *args: str, **kwargs: Any) -> subprocess.CompletedProcess[str]:
    """Run `docker compose exec {container} manage`."""
    return compose_exec(container, "manage", *args, **kwargs)


def compose_python(container: str, code: str, **kwargs: Any) -> subprocess.CompletedProcess[str]:
    """Run `docker compose exec {container} manage shell ...`."""
    return compose_manage(container, "shell", "-v", "0", "-c", code, capture_output=True)


def compose_status(tag: str) -> int:
    """Get the status of the current Docker Compose setup."""
    proc = compose("ps", "-a", "--format=json", capture_output=True)
    json_lines = proc.stdout.splitlines()
    if not json_lines:
        return err("No containers found.")

    errors = 0
    for line in json_lines:
        container_data = json.loads(line)
        # certbot container is expected to fail (it's a run-once container)
        if container_data["Service"] == "certbot":
            continue

        if (exit_code := container_data["ExitCode"]) != 0:
            errors += err(f"{container_data['Service']}: Exit code {exit_code}")

        # Make sure that the expected container version is running:
        if container_data["Service"] in COMPOSE_SERVICES:
            if container_data["Image"] != tag:
                errors += err(f"{container_data['Service']}: Image {container_data['Image']} != {tag}")

    if not errors:
        ok("All containers have started successfully.")
    return errors


def validate_container_versions(release: str, **kwargs: Any) -> int:
    """Validate that django-ca in all containers identifies correctly."""
    code = "import django_ca; print(django_ca.__version__)"
    errors = 0
    for service in COMPOSE_SERVICES:
        ver = compose_python(service, code, **kwargs).stdout.strip()
        if ver != release:
            errors += err(f"backend container identifies as {ver} instead of {release}.")

    if not errors:
        ok(f"All containers identify as {release}.")
    return errors


def test_connectivity() -> int:
    """Test internal container connectivity."""
    standalone_dir = config.ROOT_DIR / "devscripts" / "standalone"
    standalone_dest = "/usr/src/django-ca/ca/"

    errors = 0
    for service in COMPOSE_SERVICES:
        compose_cp(str(standalone_dir / "test-connectivity.py"), f"{service}:{standalone_dest}")
        proc = compose_exec(service, "./test-connectivity.py", check=False)
        if proc.returncode != 0:
            errors += 1

    if errors == 0:
        return ok("Tested connectivity.")
    return errors
