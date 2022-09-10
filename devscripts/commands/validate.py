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
# pylint: disable=missing-module-docstring  # covered in class docstring

import argparse
import importlib

from devscripts.commands import DevCommand, ParserError


class Command(DevCommand):
    """Validate various aspects of this repository not covered in unit tests."""

    modules = (("django_ca", "django-ca"),)

    def add_arguments(self, parser):
        docker_options = argparse.ArgumentParser(add_help=False)
        docker_options.add_argument(
            "--docker-prune",
            default=False,
            action="store_true",
            help="Prune system before building Docker image.",
        )
        docker_options.add_argument(
            "--no-rebuild",
            default=True,
            dest="build",
            action="store_false",
            help="Do not rebuild the image before testing.",
        )

        subcommands = parser.add_subparsers(dest="subcommand", required=True)
        subcommands.add_parser("state")
        subcommands.add_parser("docker", parents=[docker_options])
        compose_parser = subcommands.add_parser(
            "docker-compose", help="Validate docker-compose setup.", parents=[docker_options]
        )
        compose_parser.add_argument(
            "--no-tutorial",
            dest="tutorial",
            default=True,
            action="store_false",
            help="Do not test the tutorial.",
        )
        compose_parser.add_argument(
            "--no-update",
            dest="update",
            default=True,
            action="store_false",
            help="Do not test the update from the last version.",
        )
        compose_parser.add_argument(
            "--no-acme", dest="acme", default=True, action="store_false", help="Do not test ACMEv2."
        )
        subcommands.add_parser("wheel")

    def handle(self, args):
        # Validation modules is imported on execution so that external libraries used there do not
        # automatically become dependencies for all other dev.py commands.
        submodule = importlib.import_module(f"devscripts.validation.{args.subcommand.replace('-', '_')}")

        release = self.django_ca.__version__  # pylint: disable=no-member  # from lazy import

        if args.subcommand == "state":
            submodule.validate()
        elif args.subcommand == "docker":
            submodule.validate(release=release, prune=args.docker_prune, build=args.build)
        elif args.subcommand == "docker-compose":
            submodule.validate(
                release=release,
                prune=args.docker_prune,
                build=args.build,
                tutorial=args.tutorial,
                update=args.update,
                acme=args.acme,
            )
        elif args.subcommand == "wheel":
            submodule.validate(release)
        else:  # pragma: no cover
            # COVERAGE NOTE: This should not happen, parser catches all errors.
            raise ParserError("Unknown subcommand.")
