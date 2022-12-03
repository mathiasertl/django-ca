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

import os
import subprocess
import sys

from devscripts import config
from devscripts.commands import DevCommand
from devscripts.out import err, info, ok


class Command(DevCommand):
    """Build the Docker image using various base images."""

    def add_arguments(self, parser):
        project_config = config.get_project_config()
        parser.add_argument(
            "-i",
            "--image",
            action="append",
            dest="images",
            choices=project_config["docker"]["alpine-images"],
            metavar=project_config["docker"]["metavar"],
            help="Base images to test on, may be given multiple times.",
        )
        parser.add_argument(
            "--no-cache", default=False, action="store_true", help="Use Docker cache to speed up builds."
        )
        parser.add_argument(
            "--fail-fast", action="store_true", default=False, help="Stop if any docker process fails."
        )
        parser.add_argument("--keep-image", action="store_true", default=False, help="Do not remove images.")

    def handle(self, args):
        docker_runs = []

        project_config = config.get_project_config()
        images = args.images or project_config["docker"]["alpine-images"]
        for image in images:
            info(f"### Testing {image} ###")
            tag = f"django-ca-test-{image}"

            cmd = ["docker", "build"]

            if args.no_cache:
                cmd.append("--no-cache")
            if image != "default":
                cmd += ["--build-arg", f"IMAGE={image}"]

            cmd += [
                "-t",
                tag,
            ]
            cmd.append(".")

            print(" ".join(cmd))

            logdir = ".docker"
            logpath = os.path.join(logdir, f"{image}.log")
            if not os.path.exists(logdir):
                os.makedirs(logdir)

            env = dict(os.environ, DOCKER_BUILDKIT="1")

            try:
                with subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env
                ) as proc, open(logpath, "bw") as stream:
                    while True:
                        byte = proc.stdout.read(1)
                        if byte:
                            sys.stdout.buffer.write(byte)
                            sys.stdout.flush()
                            stream.write(byte)
                            # logfile.flush()
                        else:
                            break

                if proc.returncode == 0:
                    # pylint: disable-next=consider-using-f-string  # just more convenient
                    ok(f"{image} passed.")
                    docker_runs.append({"image": image, "success": True, "error": ""})
                else:
                    failed_str = f"# {image} failed: return code {proc.returncode}. #"

                    # pylint: disable-next=consider-using-f-string  # just more convenient
                    err("%s\n%s\n%s\n\n" % ("#" * len(failed_str), failed_str, "#" * len(failed_str)))
                    docker_runs.append(
                        {
                            "image": image,
                            "success": False,
                            "error": f"return code: {proc.returncode}",
                        }
                    )

            except Exception as e:  # pylint: disable=broad-except; to make sure we test all images
                msg = f"{image}: {type(e).__name__} {e}"
                docker_runs.append({"image": image, "success": False, "error": msg})
                err(f"\n{msg}\n")
                if args.fail_fast:
                    sys.exit(1)
            finally:
                if not args.keep_image:
                    self.run("docker", "image", "rm", tag, check=False)

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
