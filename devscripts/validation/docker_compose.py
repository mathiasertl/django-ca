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

"""Functions for validating docker compose and the respective tutorial."""

import argparse
import os
import shutil
import subprocess
import tempfile
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import yaml

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from devscripts import config, utils
from devscripts.commands import CommandError, DevCommand
from devscripts.docker import (
    compose_cp,
    compose_exec,
    compose_manage,
    compose_status,
    compose_test_connectivity,
    compose_validate_container_versions,
)
from devscripts.out import err, info, ok
from devscripts.versions import get_last_version


@contextmanager
def _compose_up(remove_volumes: bool = True, **kwargs: Any) -> Iterator[None]:
    try:
        utils.run(["docker", "compose", "up", "-d"], **kwargs)
        yield
    finally:
        down = ["docker", "compose", "down"]
        if remove_volumes is True:
            down.append("-v")
        down_kwargs = {}
        if "env" in kwargs:
            down_kwargs["env"] = kwargs["env"]

        utils.run(down, **down_kwargs)


def _openssl_verify(ca_file: str, cert_file: str, **kwargs: Any) -> "subprocess.CompletedProcess[Any]":
    return utils.run(
        ["openssl", "verify", "-CAfile", ca_file, "-crl_download", "-crl_check", cert_file], **kwargs
    )


def _openssl_ocsp(
    ca_file: str, cert_file: str, url: str, **kwargs: Any
) -> "subprocess.CompletedProcess[Any]":
    return utils.run(
        [
            "openssl",
            "ocsp",
            "-CAfile",
            ca_file,
            "-issuer",
            ca_file,
            "-cert",
            cert_file,
            "-resp_text",
            "-url",
            url,
        ],
        **kwargs,
    )


def _validate_crl_ocsp(
    ca_file: str, cert_file: str, cert_subject: str, already_revoked: bool = False
) -> None:
    """Test OpenSSL CRL and OCSP validation.

    This only tests the CRL for the root CA. It's the test suites job to test the views in more detail.
    """
    with open(cert_file, "rb") as stream:
        cert = x509.load_pem_x509_certificate(stream.read())

    # Get the OCSP url from the certificate
    aia = cast(
        x509.AuthorityInformationAccess,
        cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value,
    )
    ocsp_ad = next(ad for ad in aia if ad.access_method == AuthorityInformationAccessOID.OCSP)
    ocsp_url = ocsp_ad.access_location.value

    if not already_revoked:
        _openssl_verify(ca_file, cert_file)
        _openssl_ocsp(ca_file, cert_file, ocsp_url)

        compose_manage("frontend", "revoke_cert", cert_subject)

        # Still okay, because CRL is cached
        _openssl_verify(ca_file, cert_file)

    # Re-cache CRLs
    compose_manage("backend", "generate_crls")
    time.sleep(1)  # give celery task some time

    # "openssl ocsp" always returns 0 if it retrieves a valid OCSP response, even if the cert is revoked
    proc = _openssl_ocsp(ca_file, cert_file, ocsp_url, capture_output=True, text=True)
    assert "Cert Status: revoked" in proc.stdout

    # Make sure that CRL validation fails now too
    try:
        _openssl_verify(ca_file, cert_file, capture_output=True, text=True)
    except subprocess.CalledProcessError as ex:
        # OpenSSL in Ubuntu 20.04 outputs this on stdout, in 22.04 it goes to stderr
        assert "verification failed" in ex.stdout or "verification failed" in ex.stderr
    else:
        raise RuntimeError("Certificate is not revoked in CRL.")

    ok("CRL and OCSP validation works.")


def get_postgres_version(path: Path | str) -> str:
    """Get the PostgreSQL version in the current compose.yaml."""
    with open(path, encoding="utf-8") as stream:
        parsed_data = yaml.safe_load(stream)
    return parsed_data["services"]["db"]["image"].split(":")[1].split("-")[0]  # type: ignore[no-any-return]


def test_update(docker_tag: str, release: str) -> int:  # noqa: PLR0915
    """Validate updating with docker compose."""
    info("Validating docker compose update...")
    errors = 0
    # Get the last release, so we can update
    last_release = get_last_version()

    with tempfile.TemporaryDirectory() as tmpdir:
        last_release_dest = utils.git_archive(last_release, tmpdir)
        shutil.copy(last_release_dest / "compose.yaml", tmpdir)
        standalone_dir = last_release_dest / "devscripts" / "standalone"
        standalone_dest = "/usr/src/django-ca/ca/"

        with utils.chdir(tmpdir):
            # Add a very basic .env file
            with open(".env", "w", encoding="utf-8") as stream:
                stream.write(
                    """DJANGO_CA_CA_DEFAULT_HOSTNAME=localhost
DJANGO_CA_CA_ENABLE_ACME=true
POSTGRES_PASSWORD=mysecretpassword
"""
                )

            # Start previous version
            info(f"Start previous version ({last_release}).")
            with _compose_up(remove_volumes=False, env=dict(os.environ, DJANGO_CA_VERSION=last_release)):
                # Make sure old containers started properly
                errors += compose_status(f"{docker_tag.split(':')[0]}:{last_release}")

                # Make sure we have started the right version
                compose_validate_container_versions(last_release)

                info("Create test data...")
                compose_cp(str(standalone_dir / "create-testdata.py"), f"backend:{standalone_dest}")
                compose_cp(str(standalone_dir / "create-testdata.py"), f"frontend:{standalone_dest}")
                compose_exec("backend", "./create-testdata.py", "--env", "backend")
                compose_exec("frontend", "./create-testdata.py", "--env", "frontend")

                compose_manage("backend", "generate_crls")
                compose_manage("backend", "generate_ocsp_keys")

                # Write root CA and cert to disk for OpenSSL validation
                ca_subject = "rsa.example.com"  # created by create-testdata.py
                with open("ca.pem", "w", encoding="utf-8") as stream:
                    compose_manage("backend", "view_ca", "--output-format=PEM", ca_subject, stdout=stream)
                with open("cert.pem", "w", encoding="utf-8") as stream:
                    compose_manage(
                        "frontend", "view_cert", "--output-format=PEM", f"cert.{ca_subject}", stdout=stream
                    )

                # Test CRL and OCSP validation
                _validate_crl_ocsp("ca.pem", "cert.pem", f"cert.{ca_subject}")

            old_postgres_version = get_postgres_version("compose.yaml")
            new_postgres_version = get_postgres_version(config.ROOT_DIR / "compose.yaml")

            # Backup database if there was a PostgreSQL update
            if old_postgres_version != new_postgres_version:
                info(
                    f"PostgreSQL update ({old_postgres_version} -> {new_postgres_version}) detected, "
                    f"backing up database..."
                )
                utils.run(["docker", "compose", "up", "-d", "db"], env={"DJANGO_CA_VERSION": release})
                with open("backup.sql", "w", encoding="utf-8") as stream:
                    utils.run(
                        ["docker", "compose", "exec", "db", "pg_dump", "-U", "postgres", "-d", "postgres"],
                        env={"DJANGO_CA_VERSION": release},
                        stdout=stream,
                    )
            # Copy new Docker Compose file
            shutil.copy(config.ROOT_DIR / "compose.yaml", tmpdir)
            ok("Updated compose.yaml")

            # Apply backup if there was a PostreSQL update
            if old_postgres_version != new_postgres_version:
                info("Applying PostgreSQL backup due to version change...")
                utils.run(["docker", "compose", "up", "-d", "db"], env={"DJANGO_CA_VERSION": release})

                # Wait for database to come up
                for _i in range(10):
                    try:
                        utils.run(
                            ["docker", "compose", "exec", "db", "nc", "-z", "localhost:5432"],
                            env={"DJANGO_CA_VERSION": release},
                        )
                        break
                    except subprocess.SubprocessError:
                        time.sleep(1)

                with open("backup.sql", "rb") as stream:
                    utils.run(
                        ["docker", "compose", "exec", "-T", "db", "psql", "-U", "postgres", "-d", "postgres"],
                        env={"DJANGO_CA_VERSION": release},
                        stdin=stream,
                    )

            # Path to validation script in the **new** version
            validation_script = config.ROOT_DIR / "devscripts" / "standalone" / "validate-testdata.py"

            # Start and check new version
            info(f"Start current version ({release}).")
            with _compose_up(env=dict(os.environ, DJANGO_CA_VERSION=release)):
                # Make sure containers started properly
                errors += compose_status(docker_tag)

                # Make sure we have the new version
                compose_validate_container_versions(release)

                # Makse sure we can reach everything
                compose_test_connectivity()

                info("Validate test data...")
                compose_cp(str(validation_script), f"backend:{standalone_dest}")
                compose_cp(str(validation_script), f"frontend:{standalone_dest}")
                compose_exec("backend", "./validate-testdata.py", "--env", "backend")
                compose_exec("frontend", "./validate-testdata.py", "--env", "frontend")

                # Test CRL and OCSP validation
                _validate_crl_ocsp("ca.pem", "cert.pem", f"cert.{ca_subject}", already_revoked=True)

                ok("Testdata still present after update.")

    return errors


def test_acme(release: str, image: str) -> int:
    """Test ACMEv2 validation."""
    info(f"Validating ACMVEv2 implementation on {image}...")

    compose_override = config.DEVSCRIPTS_FILES / "compose.certbot.yaml"
    compose_files = f"compose.yaml:{compose_override}"
    environ = dict(os.environ, COMPOSE_FILE=compose_files, DJANGO_CA_VERSION=release)
    errors = 0

    extra_certonly_args = []
    if image in ("ubuntu:focal",):
        # ubuntu:focal does not always run non-interactively if --manual-public-ip-logging-ok is not given.
        # This option is deprecated in newer certbot versions:
        #   https://community.letsencrypt.org/t/manual-public-ip-logging-ok-deprecated-and-now-what/199274
        extra_certonly_args.append("--manual-public-ip-logging-ok")

    with tempfile.TemporaryDirectory() as tmpdir:
        dest = utils.git_archive("HEAD", tmpdir)

        with utils.chdir(dest):
            # build containers
            utils.run(["docker", "compose", "build", "--build-arg", f"IMAGE={image}"], env=environ)

            # Start containers
            with _compose_up(env=environ):
                compose_validate_container_versions(release, env=environ)
                compose_manage(
                    "backend",
                    "init_ca",
                    "--path-length=1",
                    "Root",
                    "CN=Root",
                    env=environ,
                )
                compose_manage(
                    "backend",
                    "init_ca",
                    "--acme-enable",
                    "--parent=Root",
                    "--path=ca/shared",
                    "Child",
                    "CN=Child",
                    env=environ,
                )
                try:
                    compose_exec("certbot", "certbot", "register", stdout=subprocess.DEVNULL, env=environ)
                    compose_exec(
                        "certbot",
                        "django-ca-test-validation.sh",
                        "http",
                        "http-01.example.com",
                        *extra_certonly_args,
                        env=environ,
                    )
                    ok("Created certificate via a http-01 challenge.")
                    compose_exec(
                        "certbot",
                        "django-ca-test-validation.sh",
                        "dns",
                        "dns-01.example.com",
                        *extra_certonly_args,
                        env=environ,
                    )
                    ok("Created certificate via a dns-01 challenge.")
                except subprocess.SubprocessError as ex:
                    err(f"Error testing {image}: {ex}.")
                    errors += 1

    return errors


class Command(DevCommand):
    """Class implementing the ``dev.py validate docker-compose`` command."""

    modules = (("django_ca", "django-ca"),)
    django_ca: ModuleType
    help_text = "Validate Docker Compose setup."

    @property
    def parser_parents(self) -> Sequence[argparse.ArgumentParser]:
        # TYPEHINT NOTE: It's a subcommand, so we know parent is not None
        return [self.parent.docker_options]  # type: ignore[union-attr]

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--no-tutorial",
            dest="tutorial",
            default=True,
            action="store_false",
            help="Do not test the tutorial.",
        )
        parser.add_argument(
            "--no-update",
            dest="update",
            default=True,
            action="store_false",
            help="Do not test the update from the last version.",
        )
        parser.add_argument(
            "--no-acme", dest="acme", default=True, action="store_false", help="Do not test ACMEv2."
        )
        parser.add_argument(
            "--acme-dist", metavar="DIST", help="Test ACMEv2 only with DIST (example: ubuntu:jammy)."
        )

    def run_tutorial(self, release: str, docker_tag: str, alpine: bool = False) -> int:
        """Run the Compose tutorial."""
        errors = 0
        if alpine:
            docker_tag += "-alpine"

        defines = ["-D", "BUILD_IMAGE", "no", "-D", "RELEASE", release, "-D", "DOCKER_TAG", docker_tag]
        if alpine:
            defines += ["-D", "DOCKER_IMAGE_VARIANT", "alpine"]

        proc = utils.run(
            ["structured-tutorial", "--non-interactive", *defines, "tutorials/compose/tutorial.yaml"]
        )
        if proc.returncode != 0:
            errors += err("Error running tutorial.")
        return errors

    def handle(self, args: argparse.Namespace) -> None:
        if args.docker_prune:
            self.run("docker", "system", "prune", "-af")

        print("Validating docker compose setup...")
        if args.release:
            release = args.release
            docker_tag = self.get_docker_tag(args.release)
        elif args.build:
            release, docker_tag = self.command("build", "docker")
        else:
            release = self.django_ca.__version__
            docker_tag = self.get_docker_tag(release)

        info(f"Using {docker_tag} as docker image.")

        errors = 0

        if args.tutorial:
            info("Running tutorial...")
            errors += self.run_tutorial(release, docker_tag, alpine=False)

            info("Running tutorial with Alpine image...")
            errors += self.run_tutorial(release, docker_tag, alpine=True)

        if args.update and errors == 0:
            errors += test_update(docker_tag, release)

        if args.acme and errors == 0:
            if args.acme_dist is not None:
                errors += test_acme(release, args.acme_dist)
            else:
                for dist in config.DEBIAN_RELEASES:
                    errors += test_acme(release, f"debian:{dist}")
                for dist in config.UBUNTU_RELEASES:
                    errors += test_acme(release, f"ubuntu:{dist}")

        if errors != 0:
            raise CommandError(f"{errors} found.")
