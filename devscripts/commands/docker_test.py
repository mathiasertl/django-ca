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

"""The docker-test subcommand generates the Docker image using various base images."""

import argparse
import functools
import io
import shlex
import subprocess
import sys
from multiprocessing.pool import Pool
from pathlib import Path
from typing import TypedDict, Union

from devscripts import config
from devscripts.commands import DevCommand
from devscripts.out import err, info, ok


class DockerRunDict(TypedDict):
    """TypedDict for docker runs."""

    image: str
    success: bool
    error: str


def build_docker_image(cmd: list[str], log_path: Path, output: bool = False) -> int:
    """Run command to build a Docker image."""
    env = {"DOCKER_BUILDKIT": "1"}

    with open(log_path, "bw") as stream:
        if output:
            stdout: Union[int, io.BufferedWriter] = subprocess.PIPE
        else:
            stdout = stream
        stream.write(f"+ {shlex.join(cmd)}\n".encode())

        with subprocess.Popen(cmd, stdout=stdout, stderr=subprocess.STDOUT, env=env) as proc:
            if output:
                while True:
                    data = proc.stdout.read(16)  # type: ignore[union-attr]  # not None due to arguments
                    if data:
                        sys.stdout.buffer.write(data)
                        sys.stdout.flush()
                        stream.write(data)
                        # logfile.flush()
                    else:
                        break

    return proc.returncode


def handle_image(image: str, no_cache: bool, keep_image: bool, output: bool) -> DockerRunDict:
    """Build an image."""
    info(f"### Testing {image} ###")
    tag = f"django-ca-test-{image}"

    cmd = ["docker", "build", "--build-arg", f"IMAGE={image}", "-t", tag]

    if "alpine" in image:
        cmd += ["-f", "Dockerfile.alpine"]

    if no_cache:
        cmd.append("--no-cache")

    cmd.append(".")

    if output:
        print(shlex.join(cmd))

    logdir = Path(".docker")
    logdir.mkdir(exist_ok=True, parents=True)
    logpath = logdir / f"{image}.log"

    try:
        returncode = build_docker_image(cmd, logpath, output=output)

        if returncode == 0:
            ok(f"{image} passed.")
            return {"image": image, "success": True, "error": ""}

        failed_str = f"{image} failed: return code {returncode}."
        err(failed_str)
        return {"image": image, "success": False, "error": f"return code: {returncode}"}

    except Exception as ex:  # pylint: disable=broad-except; to make sure we test all images
        msg = f"{image}: {type(ex).__name__} {ex}"
        return {"image": image, "success": False, "error": msg}
    finally:
        if not keep_image:
            subprocess.run(
                ["docker", "image", "rm", tag],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )


def handle_parallel(
    images: tuple[str, ...], processes: int, no_cache: bool, keep_image: bool
) -> list[DockerRunDict]:
    """Handle images in parallel."""
    with Pool(processes) as pool:
        worker = functools.partial(handle_image, no_cache=no_cache, keep_image=keep_image, output=False)
        docker_runs = pool.map(worker, images)
    return docker_runs


class Command(DevCommand):
    """Class implementing the ``dev.py docker-test`` command."""

    help_text = "Build the Docker image using various base images."

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        image_metavar = (
            f"default|python:{{{config.PYTHON_RELEASES[0]}-{config.PYTHON_RELEASES[-1]}}}-"
            f"alpine{{{config.ALPINE_RELEASES[0]}-{config.ALPINE_RELEASES[-1]}}}"
        )

        parser.add_argument(
            "--no-cache", default=False, action="store_true", help="Use Docker cache to speed up builds."
        )
        parser.add_argument(
            "--fail-fast", action="store_true", default=False, help="Stop if any docker process fails."
        )
        parser.add_argument("--keep-image", action="store_true", default=False, help="Do not remove images.")
        parser.add_argument("-l", "--list", action="store_true", help="List images and exit.")
        parser.add_argument(
            "-p", "--parallel", type=int, metavar="N", help="Build N images in parallel (implies -q)."
        )
        parser.add_argument(
            "-q", "--quiet", action="store_true", default=False, help="Do not print output to terminal."
        )

        group = parser.add_mutually_exclusive_group()
        group.add_argument(
            "-i",
            "--image",
            action="append",
            dest="images",
            choices=config.ALPINE_IMAGES + config.DEBIAN_IMAGES,
            metavar=image_metavar,
            help="Base images to test on, may be given multiple times.",
        )
        group.add_argument("--debian", action="store_true", help="Only test Debian-based images.")
        group.add_argument("--alpine", action="store_true", help="Only test Alpine-based images.")

    def handle(self, args: argparse.Namespace) -> None:
        docker_runs: list[DockerRunDict] = []

        if args.images:
            images: tuple[str, ...] = tuple(args.images)
        elif args.debian:
            images = config.DEBIAN_IMAGES
        elif args.alpine:
            images = config.ALPINE_IMAGES
        else:
            images = config.ALPINE_IMAGES + config.DEBIAN_IMAGES

        if args.list:
            for image in images:
                print(image)
            return

        if args.parallel is None:
            for image in images:
                result = handle_image(image, args.no_cache, args.keep_image, output=not args.quiet)
                docker_runs.append(result)
        else:
            docker_runs = handle_parallel(
                images, args.parallel, no_cache=args.no_cache, keep_image=args.keep_image
            )

        print("\nSummary of test runs:")
        for run in docker_runs:
            if run["success"]:
                ok(f"  {run['image']}: passed.")
            else:
                err(f"  {run['image']}: {run['error']}")

        failed_images = sorted([r["image"] for r in docker_runs if not r["success"]])
        if not failed_images:
            ok("\nCongratulations :)")
        else:
            err(f"\nSome images failed ({', '.join(failed_images)})")
            sys.exit(1)
