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

"""Main validation command."""

import argparse

from validation.docker import build_docker_image
from validation.docker import validate_docker_image
from validation.docker_compose import validate_docker_compose

from dev import config  # NOQA[I001]  # pylint: disable=no-name-in-module

import django_ca

if __name__ == "__main__":
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

    parser = argparse.ArgumentParser("A collection of validation scripts.")
    parser.add_argument("-q", "--quiet", default=False, action="store_true", help="Do not display commands.")

    subparsers = parser.add_subparsers(help="Aspects to validate.", dest="command")
    subparsers.add_parser("docker", help="Validate the Docker image.", parents=[docker_options])

    compose_parser = subparsers.add_parser(
        "docker-compose", help="Validate docker-compose setup.", parents=[docker_options]
    )
    compose_parser.add_argument(
        "--no-tutorial", dest="tutorial", default=True, action="store_false", help="Do not test the tutorial."
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

    args = parser.parse_args()
    release = django_ca.__version__

    if args.command == "docker":
        docker_tag = build_docker_image(release=release, prune=args.docker_prune, build=args.build)
        validate_docker_image(release, docker_tag, quiet=args.quiet)
    elif args.command == "docker-compose":
        build_docker_image(release=release, prune=args.docker_prune, build=args.build)
        validate_docker_compose(
            release=release, tutorial=args.tutorial, update=args.update, acme=args.acme, quiet=args.quiet
        )
