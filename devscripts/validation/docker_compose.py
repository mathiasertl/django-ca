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
from dev import utils
from dev.out import err
from dev.out import info
from dev.out import ok
from dev.tutorial import start_tutorial

# pylint: enable=no-name-in-module


def _compose_exec(*args, **kwargs):
    return utils.run(["docker-compose", "exec"] + list(args), **kwargs)


def _manage(container, *args, **kwargs):
    return _compose_exec(container, "manage", *args, **kwargs)


def _run_py(container, code, **kwargs):
    return _manage(container, "shell", "-c", code, capture_output=True, text=True, **kwargs).stdout


def _validate_container_versions(release, quiet):
    errors = 0
    backend_ver = _run_py("backend", "import django_ca; print(django_ca.__version__)", quiet=quiet).strip()
    frontend_ver = _run_py("frontend", "import django_ca; print(django_ca.__version__)", quiet=quiet).strip()

    if backend_ver != frontend_ver:
        errors += err(f"frontend and backend versions differ: {frontend_ver} vs. {backend_ver}")
    elif release and backend_ver != release:
        errors += err(f"Container identifies as {backend_ver}.")
    elif release and frontend_ver != release:
        errors += err(f"Container identifies as {frontend_ver}.")
    else:
        ok(f"Container version: {backend_ver}")
    return errors


def _validate_secret_key(quiet):
    code = "from django.conf import settings; print(settings.SECRET_KEY)"
    backend_key = _run_py("backend", code, quiet=quiet).strip()
    frontend_key = _run_py("frontend", code, quiet=quiet).strip()

    if backend_key != frontend_key:
        return err(f"Secret keys do not match ({frontend_key} vs. {backend_key}")
    if len(backend_key) < 32 or len(backend_key) > 128:
        return err(f"Secret key seems to have an unusual length: {backend_key}")
    ok("Secret keys match.")
    return 0


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
        "postgres_host": "db",  # name in compose file
        "postgres_password": "random-password",
        "privkey_path": f"{_tls_cert_root}live/{_ca_default_hostname}/privkey.pem",
        "pubkey_path": f"{_tls_cert_root}live/{_ca_default_hostname}/fullchain.pem",
        "dhparam_name": "dhparam.pem",
        "certbot_root": "./",
        "tls_cert_root": _tls_cert_root,
    }

    with start_tutorial("quickstart_with_docker_compose", context, quiet) as tut:
        info(f"Temporary working directory: {os.getcwd()}")
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

        ca_key = config.FIXTURES_DIR / "root.key"
        ca_pub = config.FIXTURES_DIR / "root.pub"
        utils.create_signed_cert(_ca_default_hostname, ca_key, ca_pub, archive_privkey, archive_fullchain)

        (live_path / "privkey.pem").symlink_to(os.path.relpath(archive_privkey, live_path))
        (live_path / "fullchain.pem").symlink_to(os.path.relpath(archive_fullchain, live_path))

        with tut.run("dhparam.yaml"), tut.run("docker-compose-up.yaml"), tut.run("verify-setup.yaml"):
            ok("Containers seem to have started properly.")
            _manage("backend", "makemigrations", "--check", quiet=quiet, capture_output=True)
            _manage("frontend", "makemigrations", "--check", quiet=quiet, capture_output=True)
            errors += _validate_container_versions(release, quiet)
            errors += _validate_secret_key(quiet)

            with tut.run("setup-cas.yaml"):
                info(
                    f"""Test admin interface at

    * URL: http://{_ca_default_hostname}/admin
    * Credentials: user/nopass
"""
                )
                info("Press enter to continue...")
                input()

    return errors
