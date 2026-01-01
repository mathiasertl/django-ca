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

"""Various utility functions."""

import os
import random
import shlex
import string
import subprocess
import typing
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast

import requests

from devscripts import config
from devscripts.out import ok


@contextmanager
def chdir(path: str | os.PathLike[str]) -> Iterator[str]:
    """Context manager to temporarily change the working directory to `path`."""
    orig_cwd = os.getcwd()
    try:
        os.chdir(path)
        yield orig_cwd
    finally:
        os.chdir(orig_cwd)


def run(args: Sequence[str], **kwargs: Any) -> "subprocess.CompletedProcess[Any]":
    """Shortcut for subprocess.run()."""
    kwargs.setdefault("check", True)
    if config.SHOW_COMMANDS:
        print("+", shlex.join(args))
    if not config.SHOW_COMMAND_OUTPUT and not kwargs.get("capture_output"):
        kwargs.setdefault("stdout", subprocess.DEVNULL)
        kwargs.setdefault("stderr", subprocess.DEVNULL)
    return subprocess.run(args, **kwargs)  # noqa: PLW1510  # check set via kwargs


def git_archive(ref: str, destination: str) -> Path:
    """Export the git repository to `django-ca-{ref}/` in the given destination directory.

    `ref` may be any valid git reference, usually a git tag.
    """
    # Add a random suffix to the export destination to improve build isolation (e.g. Docker Compose will use
    # that directory name as a name for Docker images/containers).
    random_suffix = "".join(random.choice(string.ascii_lowercase) for i in range(12))
    destination = os.path.join(destination, f"django-ca-{ref}-{random_suffix}")

    if not os.path.exists(destination):
        os.makedirs(destination)

    with subprocess.Popen(["git", "archive", ref], stdout=subprocess.PIPE) as git_archive_cmd:
        with subprocess.Popen(["tar", "-x", "-C", destination], stdin=git_archive_cmd.stdout) as tar:
            # TYPEHINT NOTE: stdout is not None b/c of stdout=subprocess.PIPE
            stdout = cast(typing.IO[bytes], git_archive_cmd.stdout)
            stdout.close()
            tar.communicate()
    return Path(destination)


def test_endpoints(base_url: str, api_user: str, api_password: str, verify: str | None = None) -> int:
    """Test endpoints of a given installation."""
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
