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

"""Common functionality for dev.py subcommands."""
import argparse
import importlib
import os
import pathlib
import pkgutil
import subprocess
import sys
import typing
from typing import Any, Optional, Tuple, Union

import django

from devscripts import config, utils
from devscripts.out import err, info

if typing.TYPE_CHECKING:
    import docker  # NOQA: F401  # flake8 does not detect that this is for type-hinting.
    from docker.client import DockerClient
    from docker.models.images import Image


class CommandError(Exception):
    """Exception class for handling dev.py errors."""

    def __init__(self, value: str, code: int = 1) -> None:
        super().__init__()
        self.value = value
        self.code = code


class ParserError(CommandError):
    """Exception that allows a command to show usage information."""

    def __init__(self, value: str, code: int = 2) -> None:
        super().__init__(value, code)


class DevCommand:
    """Base class for all dev.py sub-commands."""

    _docker_client: Optional["docker.client.DockerClient"] = None

    modules: Tuple[Tuple[str, str], ...] = tuple()
    help_text: str = ""
    description = ""

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add arguments to the command line parser."""

    def handle(self, args: argparse.Namespace) -> None:
        """Method that is supposed to be implemented by sub-commands."""
        raise NotImplementedError

    def exec(self, parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
        """Default argparse entry point."""
        for mod_name, pip_name in self.modules:
            mod = importlib.import_module(mod_name)
            setattr(self, mod_name, mod)

        if args.quiet:
            config.OUTPUT_COMMANDS = False

        try:
            self.handle(args)
        except ParserError as ex:
            parser.error(ex.value)
        except CommandError as ex:
            print(f"ERROR: {ex.value}")
            sys.exit(ex.code)

    @property
    def docker(self) -> "docker":  # NOQA: F811  # flake8 detects the TYPE_CHECKING protected module.
        """Get the docker Python library."""
        return importlib.import_module("docker")

    @property
    def docker_client(self) -> "DockerClient":
        """Get the current Docker client."""
        if self._docker_client is None:
            self._docker_client = self.docker.from_env()
        return self._docker_client

    def docker_build(self, **kwargs: Any) -> "Image":
        """Build a Docker image."""
        dockerfile = kwargs.get("dockerfile", "Dockerfile")

        # make Dockerfile relative to the current path for shorter output
        if isinstance(dockerfile, pathlib.Path):
            dockerfile = dockerfile.relative_to(config.ROOT_DIR)

        if build_tag := kwargs.get("tag"):
            info(f"Build {dockerfile} as {build_tag}...")
        else:
            info(f"Build {dockerfile}...")

        try:
            return self.docker_client.images.build(**kwargs)[0]
        except self.docker.errors.BuildError as ex:
            for log_elem in ex.build_log:
                if "stream" in log_elem:
                    print(log_elem["stream"], end="")
                elif "error" in log_elem:
                    err(log_elem["error"])

            raise CommandError("Error building Docker image, see above for details.") from ex

    def docker_run(self, image: Union["Image", str], **kwargs: Any) -> bytes:
        """Run the specified Docker image."""
        if isinstance(image, str):
            info(f"Run {image}...")
        elif tags := image.tags:
            info(f"Run {tags[0]}...")
        else:
            info(f"Run {image.id}")

        try:
            # TYPE NOTE: docker is not typehinted.
            #   https://github.com/docker/docker-py/issues/2796
            return self.docker_client.containers.run(image, **kwargs)  # type: ignore[no-any-return]
        except self.docker.errors.APIError as ex:
            # Happens e.g. when you execute an unknown command in the container
            print(ex.explanation)
            raise CommandError("Error running Docker image, see above for details.") from ex
        except self.docker.errors.ContainerError as ex:
            # Happens when the executed command failed.
            print(ex.stderr.decode())
            raise CommandError("Error running Docker image, see above for details.") from ex

    def setup_django(self, settings_module: str = "ca.test_settings") -> None:
        """Call ``django.setup()`` and set ``DJANGO_SETTINGS_MODULE``."""
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", settings_module)
        django.setup()

    def run(self, *args: Union[str, "os.PathLike[str]"], check: bool = True, **kwargs: Any) -> None:
        """Shortcut to run the given command."""
        str_args = tuple(str(arg) if isinstance(arg, os.PathLike) else arg for arg in args)
        try:
            utils.run(str_args, check=check, **kwargs)
        except subprocess.CalledProcessError as ex:
            raise CommandError(f"{args[0]} returned with exit status {ex.returncode}.") from ex


class DevSubCommand(DevCommand):
    """Base class for commands that take further sub-commands."""

    # submodule of devscripts where subcommands are located
    module_name: str

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        subcommands = parser.add_subparsers(dest="subcommand")

        module = importlib.import_module(f"devscripts.{self.module_name}")
        submodules = pkgutil.iter_modules(module.__path__)
        for finder, name, is_pkg in submodules:
            submodule = importlib.import_module(f"devscripts.{self.module_name}.{name}")

            # Get Command class of the module, skip module if it doesn't contain it
            command_cls = getattr(submodule, "Command", None)
            if not command_cls or not issubclass(command_cls, DevCommand):
                continue

            command = command_cls()
            subcommand_parser = subcommands.add_parser(
                name, help=command.help_text, description=command.description
            )
            subcommand_parser.set_defaults(func=command.exec)

    def handle(self, args: argparse.Namespace) -> None:
        raise CommandError("Subcommand is must be given.")


def add_command(cmd_subparser: "argparse._SubParsersAction[argparse.ArgumentParser]", name: str) -> None:
    """Add a subcommand with the given name to the sub-command parser.

    The function expects to find ``Command`` class to be defined in `devscripts.{name}`.
    """
    mod_name = name.replace("-", "_")
    mod = importlib.import_module(f"devscripts.commands.{mod_name}")
    cmd = mod.Command()

    help_text = cmd.help_text
    description = cmd.description
    if cmd.__doc__ is not None:
        doc_lines = cmd.__doc__.splitlines()
        if not help_text:
            help_text = doc_lines[0].strip()
        if not description and len(doc_lines) > 1:
            description = " ".join(doc_lines[1:]).strip()

    cmd_parser = cmd_subparser.add_parser(name, help=help_text, description=description)
    cmd_parser.set_defaults(func=cmd.exec)
    cmd.add_arguments(cmd_parser)
