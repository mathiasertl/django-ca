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

"""Functions for validating docker-compose and the respective tutorial."""

import os
import shutil
from pathlib import Path

# pylint: disable=no-name-in-module  # false positive due to dev.py
from dev import config
from dev.out import err
from dev.tutorial import start_tutorial

# pylint: enable=no-name-in-module


def validate_docker_compose(release=None, quiet=False):
    """Validate the docker-compose file (and the tutorial)."""
    print("Validating docker-compose setup...")

    errors = 0

    docker_compose_yml = os.path.join(config.ROOT_DIR, "docker-compose.yml")
    if release:
        docker_compose_yml = os.path.join(config.DOCS_DIR, "source", "_files", release, "docker-compose.yml")

    if not os.path.exists(docker_compose_yml):
        return err(f"{docker_compose_yml}: File not found.")

    _ca_default_hostname = "localhost"
    _tls_cert_root = "/etc/certs/"
    context = {
        "ca_default_hostname": _ca_default_hostname,
        "postgres_password": "random-password",
        "privkey_path": f"{_tls_cert_root}live/{_ca_default_hostname}/privkey.pem",
        "pubkey_path": f"{_tls_cert_root}live/{_ca_default_hostname}/fullchain.pem",
        "dhparam_name": "dhparam.pem",
        "certbot_root": "./",
        "tls_cert_root": _tls_cert_root,
    }

    with start_tutorial("quickstart_with_docker_compose", context, quiet) as tut:
        tut.write_template("docker-compose.override.yml.jinja")
        tut.write_template(".env.jinja")
        shutil.copy(docker_compose_yml, ".")

        # Set up fake ACME certificates
        live_path = Path("live", _ca_default_hostname).resolve()
        live_path.mkdir(parents=True)
        archive_dir = Path("archive", _ca_default_hostname).resolve()
        archive_dir.mkdir(parents=True)
        archive_privkey = archive_dir / "privkey.pem"
        archive_fullchain = archive_dir / "fullchain.pem"

        shutil.copyfile(config.FIXTURES_DIR / "root.key", archive_privkey)
        shutil.copyfile(config.FIXTURES_DIR / "root.pub", archive_fullchain)

        (live_path / "privkey.pem").symlink_to(os.path.relpath(archive_privkey, live_path))
        (live_path / "fullchain.pem").symlink_to(os.path.relpath(archive_fullchain, live_path))

        with tut.run("dhparam.yaml"), tut.run("docker-compose-up.yaml"), tut.run("verify-setup.yaml"):
            print(os.getcwd(), os.listdir("."))
            input()

    return errors
