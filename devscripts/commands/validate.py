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

from devscripts.commands import DevCommand
from devscripts.commands import ParserError
from devscripts.validation import docker
from devscripts.validation import docker_compose
from devscripts.validation import state

import django_ca


class Command(DevCommand):
    """Validate various aspects of this repository not covered in unit tests."""

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

        parser.add_argument(
            "-q", "--quiet", default=False, action="store_true", help="Do not display commands."
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

    def handle(self, args):
        release = django_ca.__version__

        if args.subcommand == "state":
            state.validate()
        elif args.subcommand == "docker":
            docker.validate(release=release, prune=args.docker_prune, build=args.build, quiet=args.quiet)
        elif args.subcommand == "docker-compose":
            docker_compose.validate(
                release=release,
                prune=args.docker_prune,
                build=args.build,
                tutorial=args.tutorial,
                update=args.update,
                acme=args.acme,
                quiet=args.quiet,
            )
        else:  # pragma: no cover
            # COVERAGE NOTE: This should not happen, parser catches all errors.
            raise ParserError("Unknown subcommand.")
