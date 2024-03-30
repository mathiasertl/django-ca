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
from collections.abc import Sequence
from typing import Any, Optional, Tuple, Union

import django

from devscripts import config, utils
from devscripts.out import err, info

if typing.TYPE_CHECKING:
    import docker
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
    parser: argparse.ArgumentParser

    modules: tuple[tuple[str, str], ...] = tuple()
    help_text: str = ""
    description = ""

    # Parent command if any
    parent: Optional["DevCommand"] = None

    @property
    def parser_parents(self) -> Sequence[argparse.ArgumentParser]:
        """Argument parser parents, can be overwritten by subclasses."""
        return []

    def __init__(self, **kwargs: Any) -> None:
        for key, value in kwargs.items():
            setattr(self, key, value)

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add arguments to the command line parser."""

    def get_docker_tag(self, release: str) -> str:
        """Get the docker tag for the given release."""
        return f"{config.DOCKER_TAG}:{release}"

    def handle(self, args: argparse.Namespace) -> None:
        """Method that is supposed to be implemented by sub-commands."""
        raise NotImplementedError

    def exec(self, parser: argparse.ArgumentParser, args: argparse.Namespace) -> Any:
        """Default argparse entry point."""
        for mod_name, _pip_name in self.modules:
            mod = importlib.import_module(mod_name)
            setattr(self, mod_name, mod)

        if args.show_commands:
            config.SHOW_COMMANDS = True
        if args.show_output:
            config.SHOW_COMMAND_OUTPUT = True

        try:
            return self.handle(args)
        except ParserError as ex:
            parser.error(ex.value)
        except CommandError as ex:
            print(f"ERROR: {ex.value}")
            sys.exit(ex.code)

    @property
    def docker(self) -> "docker":
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

    def run(
        self, *args: Union[str, "os.PathLike[str]"], check: bool = True, **kwargs: Any
    ) -> "subprocess.CompletedProcess[Any]":
        """Shortcut to run the given command."""
        str_args = tuple(str(arg) if isinstance(arg, os.PathLike) else arg for arg in args)
        try:
            return utils.run(str_args, check=check, **kwargs)
        except subprocess.CalledProcessError as ex:
            raise CommandError(f"{args[0]} returned with exit status {ex.returncode}.") from ex

    def command(self, *args: str) -> Any:
        """Run a dev.py command."""
        if self.parent is None:
            parser = self.parser
        else:
            parser = self.parent.parser
        parsed_args = parser.parse_args(args)
        return parsed_args.func(self.parser, parsed_args)


class DevSubCommand(DevCommand):
    """Base class for commands that take further sub-commands."""

    # submodule of devscripts where subcommands are located
    module_name: str

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        add_subcommands(parser, f"devscripts.{self.module_name}", "subcommand", parent=self)

    def handle(self, args: argparse.Namespace) -> None:
        raise CommandError("Subcommand is must be given.")


def add_subcommands(parser: argparse.ArgumentParser, path: str, dest: str = "command", **kwargs: Any) -> None:
    """Function to add subcommands gin `path` to `parser`."""
    commands = parser.add_subparsers(dest=dest)

    # Get a list of submodules:
    module = importlib.import_module(path)
    submodules = pkgutil.iter_modules(module.__path__)

    for _finder, name, _is_pkg in submodules:
        # Import module
        submodule = importlib.import_module(f"{path}.{name}")

        # Try to find the "Command" class in the module
        command_cls = getattr(submodule, "Command", None)
        if not command_cls or not issubclass(command_cls, DevCommand):
            continue

        # Instantiate command class and add its arguments
        command = command_cls(parser=parser, **kwargs)

        name = name.replace("_", "-")
        description = command.description
        if not description:
            description = command.help_text

        subcommand_parser = commands.add_parser(
            name, help=command.help_text, description=description, parents=command.parser_parents
        )
        subcommand_parser.set_defaults(func=command.exec)
        command.add_arguments(subcommand_parser)
