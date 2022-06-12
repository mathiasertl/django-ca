#!/usr/bin/env python3
#
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

"""Various utillity functions."""

import io
import os
import subprocess
import tempfile
from contextlib import contextmanager
from contextlib import redirect_stderr
from contextlib import redirect_stdout

import docker


@contextmanager
def redirect_output():
    """Context manager to redirect both stdout and stderr."""
    out = io.StringIO()
    with redirect_stdout(out), redirect_stderr(out):
        yield out


@contextmanager
def chdir(path):
    """Context manager to temporarily change the working directory to `path`."""
    orig_cwd = os.getcwd()
    try:
        os.chdir(path)
        yield orig_cwd
    finally:
        os.chdir(orig_cwd)


def docker_run(*args, **kwargs):
    """Shortcut for running a docker command."""
    # pylint: disable=subprocess-run-check  # is in kwargs/defaults
    kwargs.setdefault("check", True)
    return subprocess.run(["docker", "run", "--rm"] + list(args), **kwargs)


@contextmanager
def docker_container(tag, **kwargs):
    """Context manager to start a docker container and remove it afterwards."""
    client = docker.from_env()
    kwargs.setdefault("detach", True)

    container = client.containers.run(tag, **kwargs)
    try:
        yield container
    finally:
        container.reload()
        container.kill()
        try:
            container.remove(v=True)
        except docker.errors.NotFound:
            pass


@contextmanager
def docker_network(name):
    """Context manager to create a Docker network and remove it after use."""
    client = docker.from_env()
    network = client.networks.create(name)
    try:
        yield network
    finally:
        network.reload()
        for container in network.containers:
            network.disconnect(container)
        network.remove()


@contextmanager
def tmpdir(**kwargs):
    """Context manager to temporarily change the working directory to a temporary directory."""

    with tempfile.TemporaryDirectory(**kwargs) as tmpdirname, chdir(tmpdirname):
        yield tmpdirname
