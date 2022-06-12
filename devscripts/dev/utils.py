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
import shlex
import subprocess
import tempfile
from contextlib import contextmanager
from contextlib import redirect_stderr
from contextlib import redirect_stdout

import yaml
from jinja2 import Environment

from . import config

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader


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


@contextmanager
def console_include(path, context):
    """Run a console-include from the django_ca_sphinx Sphinx extension."""
    env = Environment(autoescape=False)

    with open(os.path.join(config.DOC_TEMPLATES_DIR, path), encoding="utf-8") as stream:
        commands = yaml.load(stream, Loader=Loader)["commands"]

    clean_commands = []

    try:
        for command in commands:
            args = shlex.split(env.from_string(command["command"]).render(**context))
            with redirect_output():
                print("+", shlex.join(args))
                subprocess.run(args, check=True)

            for clean in reversed(command.get("clean", [])):
                clean_commands.append(shlex.split(env.from_string(clean).render(**context)))

        yield
    finally:
        for args in reversed(clean_commands):
            print("+", shlex.join(args))
            subprocess.run(args, check=False)


def docker_run(*args, **kwargs):
    """Shortcut for running a docker command."""
    # pylint: disable=subprocess-run-check  # is in kwargs/defaults
    kwargs.setdefault("check", True)
    return subprocess.run(["docker", "run", "--rm"] + list(args), **kwargs)


@contextmanager
def tmpdir(**kwargs):
    """Context manager to temporarily change the working directory to a temporary directory."""

    with tempfile.TemporaryDirectory(**kwargs) as tmpdirname, chdir(tmpdirname):
        yield tmpdirname
