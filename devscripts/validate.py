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

from validation.docker import validate_docker_image
from validation.docker_compose import validate_docker_compose

if __name__ == "__main__":
    parser = argparse.ArgumentParser("A collection of validation scripts.")
    parser.add_argument("-q", "--quiet", default=False, action="store_true", help="Display commands.")

    subparsers = parser.add_subparsers(help="Aspects to validate.", dest="command")
    docker_parser = subparsers.add_parser("docker", help="Validate the Docker image.")
    docker_parser.add_argument(
        "--no-docker-prune",
        default=True,
        dest="docker_prune",
        action="store_false",
        help="Prune system before building Docker image.",
    )
    docker_parser.add_argument(
        "--no-rebuild",
        default=True,
        dest="build",
        action="store_false",
        help="Do not rebuild the image before testing.",
    )

    subparsers.add_parser("docker-compose", help="Validate docker-compose setup.")

    args = parser.parse_args()

    if args.command == "docker":
        validate_docker_image(prune=args.docker_prune, build=args.build, quiet=args.quiet)
    elif args.command == "docker-compose":
        validate_docker_compose(quiet=args.quiet)
