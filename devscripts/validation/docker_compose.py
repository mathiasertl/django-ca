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
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import typing
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from typing import Any, Union

import requests
import yaml

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from devscripts import config, utils
from devscripts.commands import CommandError, DevCommand
from devscripts.out import err, info, ok
from devscripts.tutorial import start_tutorial
from devscripts.validation.docker import docker_cp
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


def compose_status() -> None:
    """Assert that all containers have started successfully."""
    proc = utils.run(["docker", "compose", "ps", "-a", "--format=json"], capture_output=True, text=True)
    errors = 0
    for line in proc.stdout.splitlines():
        container_data = json.loads(line)
        if (exit_code := container_data["ExitCode"]) != 0:
            errors += err(f"{container_data['Service']}: Exit code {exit_code}")

    if errors != 0:
        raise RuntimeError(f"{errors} container(s) have not started successfully.")
    ok("All containers have started successfully.")


def _compose_exec(*args: str, **kwargs: Any) -> "subprocess.CompletedProcess[Any]":
    cmd = ["docker", "compose", "exec", *kwargs.pop("compose_args", []), *args]
    return utils.run(cmd, **kwargs)


def _manage(container: str, *args: str, **kwargs: Any) -> "subprocess.CompletedProcess[Any]":
    return _compose_exec(container, "manage", *args, **kwargs)


def _sign_cert(container: str, ca: str, csr: str, **kwargs: Any) -> str:
    subject = f"signed-in-{container}.{ca.lower()}.example.com"

    _manage(
        container,
        "sign_cert",
        f"--ca={ca}",
        f"--subject=CN={subject}",
        input=csr.encode("ascii"),
        compose_args=["-T"],
        **kwargs,
    )
    return subject


def _run_py(container: str, code: str, env: dict[str, str] | None = None) -> str:
    proc = _manage(container, "shell", "-v", "0", "-c", code, capture_output=True, text=True, env=env)
    return typing.cast(str, proc.stdout)  # is a str because of text=True above


def _openssl_verify(ca_file: str, cert_file: str, **kwargs: Any) -> "subprocess.CompletedProcess[Any]":
    return utils.run(
        ["openssl", "verify", "-CAfile", ca_file, "-crl_download", "-crl_check", cert_file], **kwargs
    )


def der_certificate_to_pem(source: Path, destination: Path) -> None:
    """Convert a DER certificate to a PEM."""
    with open(source, "rb") as stream:
        data = stream.read()
    certificate = x509.load_der_x509_certificate(data)
    pem = certificate.public_bytes(Encoding.PEM)
    with open(destination, "wb") as stream:
        stream.write(pem)


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


def _validate_container_versions(release: str, env: dict[str, str] | None = None) -> int:
    errors = 0
    beat_ver = _run_py("backend", "import django_ca; print(django_ca.__version__)", env=env).strip()
    backend_ver = _run_py("backend", "import django_ca; print(django_ca.__version__)", env=env).strip()
    frontend_ver = _run_py("frontend", "import django_ca; print(django_ca.__version__)", env=env).strip()

    if beat_ver != backend_ver:
        errors += err(f"beat and backend versions differ: {frontend_ver} vs. {backend_ver}")
    if backend_ver != frontend_ver:
        errors += err(f"frontend and backend versions differ: {frontend_ver} vs. {backend_ver}")
    if beat_ver != release:
        errors += err(f"backend container identifies as {backend_ver} instead of {release}.")
    if backend_ver != release:
        errors += err(f"backend container identifies as {backend_ver} instead of {release}.")
    if frontend_ver != release:
        errors += err(f"frontend container identifies as {frontend_ver} instead of {release}.")

    return errors


def _validate_secret_key() -> int:
    code = "from django.conf import settings; print(settings.SECRET_KEY)"
    beat_key = _run_py("beat", code).strip()
    backend_key = _run_py("backend", code).strip()
    frontend_key = _run_py("frontend", code).strip()

    if beat_key != backend_key:
        return err(f"Secret key in beat do not match backend: ({frontend_key} vs. {backend_key}")
    if backend_key != frontend_key:
        return err(f"Secret keys do not match ({frontend_key} vs. {backend_key}")
    if len(backend_key) < 32 or len(backend_key) > 128:
        return err(f"Secret key seems to have an unusual length: {backend_key}")
    ok("Secret keys match.")
    return 0


def _validate_crl_ocsp(
    ca_file: str, cert_file: str, cert_subject: str, already_revoked: bool = False
) -> None:
    """Test OpenSSL CRL and OCSP validation.

    This only tests the CRL for the root CA. It's the test suites job to test the views in more detail.
    """
    with open(cert_file, "rb") as stream:
        cert = x509.load_pem_x509_certificate(stream.read())

    # Get the OCSP url from the certificate
    aia = typing.cast(
        x509.AuthorityInformationAccess,
        cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value,
    )
    ocsp_ad = next(ad for ad in aia if ad.access_method == AuthorityInformationAccessOID.OCSP)
    ocsp_url = ocsp_ad.access_location.value

    if not already_revoked:
        _openssl_verify(ca_file, cert_file)
        _openssl_ocsp(ca_file, cert_file, ocsp_url)

        _manage("frontend", "revoke_cert", cert_subject)

        # Still okay, because CRL is cached
        _openssl_verify(ca_file, cert_file)

    # Re-cache CRLs
    _manage("backend", "cache_crls")
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


def _test_connectivity(standalone_dir: Path) -> int:
    standalone_dest = "/usr/src/django-ca/ca/"
    cwd_basename = os.path.basename(os.getcwd())
    errors = 0

    for typ in ["backend", "frontend"]:
        container = f"{cwd_basename}-{typ}-1"
        docker_cp(str(standalone_dir / "test-connectivity.py"), container, standalone_dest)

        proc = _compose_exec(typ, "./test-connectivity.py")
        if proc.returncode != 0:
            errors += 1
    if errors == 0:
        return ok("Tested connectivity.")

    err("Error testing network connectivity")
    return errors


def _sign_certificates(csr: str) -> str:
    # Sign some certs in the backend
    cert_subject = _sign_cert("backend", "Root", csr)
    _sign_cert("backend", "Intermediate", csr)

    # Sign certs in the frontend (only intermediate works, root was created in backend)
    _sign_cert("frontend", "Intermediate", csr)

    try:
        _sign_cert("frontend", "Root", csr, capture_output=True)
    except subprocess.CalledProcessError as ex:
        assert re.search(rb"Private key file not found\.", ex.stderr), (ex.stdout, ex.stderr)
    else:
        raise RuntimeError("Was able to sign root cert in frontend.")

    return cert_subject


def validate_endpoints(base_url: str, api_user: str, api_password: str, verify: str | None = None) -> None:
    """Validate all endpoints of the setup."""
    # Test that HTTPS connection and admin interface is working:
    resp = requests.get(f"{base_url}/admin/", verify=verify, timeout=10)
    resp.raise_for_status()

    # Test static files
    resp = requests.get(f"{base_url}/static/admin/css/base.css", verify=verify, timeout=10)
    resp.raise_for_status()

    # Test the REST API
    resp = requests.get(f"{base_url}/api/ca/", auth=(api_user, api_password), verify=verify, timeout=10)
    resp.raise_for_status()

    # Test (principal) ACME connection
    resp = requests.get(f"{base_url}/acme/directory/", verify=verify, timeout=10)
    resp.raise_for_status()


def test_tutorial(release: str) -> int:  # pylint: disable=too-many-locals  # noqa: PLR0915
    """Validate the docker compose quickstart tutorial."""
    info("Validating tutorial...")
    errors = 0
    standalone_dir = config.ROOT_DIR / "devscripts" / "standalone"
    docker_compose_yml = config.ROOT_DIR / "compose.yaml"
    if not docker_compose_yml.exists():
        return err(f"{docker_compose_yml}: File not found.")

    # Calculate some static paths
    ca_key = config.FIXTURES_DIR / "root.key"
    ca_pub = config.FIXTURES_DIR / "root.pub"
    csr_path = config.FIXTURES_DIR / "root-cert.csr"

    # Read CSR so we can pass it in context
    with open(csr_path, "rb") as stream:
        csr = stream.read()

    # Convert CSR to PEM (sign_cert only accepts PEM on stdin)
    loaded_csr = x509.load_der_x509_csr(csr)
    csr_pem = loaded_csr.public_bytes(Encoding.PEM).decode("ascii")

    _ca_default_hostname = "localhost"
    _tls_cert_root = "/etc/certs/"
    context = {
        "ca_default_hostname": _ca_default_hostname,
        "ca_url_path": "",
        "postgres_host": "db",  # name in compose file
        "postgres_password": "random-password",
        "privkey_path": f"{_tls_cert_root}live/{_ca_default_hostname}/privkey.pem",
        "pubkey_path": f"{_tls_cert_root}live/{_ca_default_hostname}/fullchain.pem",
        "dhparam_name": "dhparam.pem",
        "certbot_root": "./",
        "tls_cert_root": _tls_cert_root,
        "csr": csr_pem,
        "django_ca_version": release,
    }

    with start_tutorial("quickstart_with_docker_compose", context) as tut:
        cwd = Path(os.getcwd())
        info(f"# Running in {cwd}")
        tut.write_template("localsettings.yaml.jinja")
        shutil.copy(docker_compose_yml, cwd)
        tut.write_template("compose.override.yaml.jinja")
        tut.write_template(".env.jinja")
        shutil.copy(docker_compose_yml, cwd)

        # Convert DER certificates from fixtures to PEM (requests needs PEM certificates).
        ca_pub_pem = cwd / "https-root.pem"
        der_certificate_to_pem(ca_pub, ca_pub_pem)

        # Set up fake ACME certificates
        live_path = Path("live", _ca_default_hostname).resolve()
        live_path.mkdir(parents=True)
        archive_dir = Path("archive", _ca_default_hostname).resolve()
        archive_dir.mkdir(parents=True)
        archive_privkey = archive_dir / "privkey.pem"
        archive_fullchain = archive_dir / "fullchain.pem"

        utils.create_signed_cert(_ca_default_hostname, ca_key, ca_pub, archive_privkey, archive_fullchain)

        (live_path / "privkey.pem").symlink_to(os.path.relpath(archive_privkey, live_path))
        (live_path / "fullchain.pem").symlink_to(os.path.relpath(archive_fullchain, live_path))

        with tut.run("dhparam.yaml"), tut.run("docker-compose-up.yaml"), tut.run("verify-setup.yaml"):
            compose_status()

            # Validate that the container versions match the expected version
            errors += _validate_container_versions(release)

            # Validate that the secret keys match
            errors += _validate_secret_key()

            # Test connectivity
            errors += _test_connectivity(standalone_dir)

            with tut.run("setup-cas.yaml"):  # Creates initial CAs
                ok("Setup certificate authorities.")
                with tut.run("list_cas.yaml"):
                    pass  # nothing really to do here
                with tut.run("sign_cert.yaml"), tut.run("sign_cert_stdin.yaml"):
                    pass  # nothing really to do here

                # test number of CAs
                cas = _manage("frontend", "list_cas", capture_output=True, text=True).stdout.splitlines()
                assert len(cas) == 2, f"Found {len(cas)} CAs."

                # sign some certs
                cert_subject = _sign_certificates(csr_pem)

                certs = _manage("frontend", "list_certs", capture_output=True, text=True).stdout.splitlines()
                assert len(certs) == 5, f"Found {len(certs)} certs instead of 5."
                ok("Signed certificates.")

                # Restart everything to make sure that all data survives a restart.
                utils.run(["docker", "compose", "down"])
                utils.run(["docker", "compose", "up", "-d"], env={"DJANGO_CA_VERSION": release})
                ok("Restarted docker containers.")

                # Write root CA and cert to disk for OpenSSL validation
                with open("root.pem", "w", encoding="utf-8") as stream:
                    _manage("backend", "dump_ca", "Root", stdout=stream)
                with open(f"{cert_subject}.pem", "w", encoding="utf-8") as stream:
                    _manage("frontend", "dump_cert", cert_subject, stdout=stream)

                # Test CRL and OCSP validation
                _validate_crl_ocsp("root.pem", f"{cert_subject}.pem", cert_subject)

                # Test all endpoints
                validate_endpoints("https://localhost", "user", "nopass", verify=str(ca_pub_pem))

                # Finally some manual testing
                info(
                    f"""Test admin interface at

    * URL: https://{_ca_default_hostname}/admin/
    * Credentials: user/nopass
"""
                )
                info(f"Working directory is {os.getcwd()}")
                info("Press enter to continue...")
                input()

                # test again that we find the correct number of CAs/certs, this way we can be sure that the
                # restart didn't break the database
                cas = _manage("frontend", "list_cas", capture_output=True, text=True).stdout.splitlines()
                assert len(cas) == 2, f"Found {len(cas)} CAs instead of 2."
                certs = _manage("frontend", "list_certs", capture_output=True, text=True).stdout.splitlines()
                # only four now, as one was revoked:
                assert len(certs) == 4, f"Found {len(certs)} certs instead of 4."

                # sign certificates again to make sure that CAs are still present
                _sign_certificates(csr_pem)

    if errors == 0:
        ok("Tutorial successfully validated.")

    return errors


def get_postgres_version(path: Path | str) -> str:
    """Get the PostgreSQL version in the current compose.yaml."""
    with open(path, encoding="utf-8") as stream:
        parsed_data = yaml.safe_load(stream)
    return parsed_data["services"]["db"]["image"].split(":")[1].split("-")[0]  # type: ignore[no-any-return]


def test_update(release: str) -> int:  # noqa: PLR0915
    """Validate updating with docker compose."""
    info("Validating docker compose update...")
    errors = 0
    # Get the last release, so we can update
    last_release = get_last_version()

    with tempfile.TemporaryDirectory() as tmpdir:
        last_release_dest = utils.git_archive(last_release, tmpdir)
        shutil.copy(last_release_dest / "compose.yaml", tmpdir)
        standalone_dir = last_release_dest / "devscripts" / "standalone"
        backend = f"{os.path.basename(tmpdir)}-backend-1"
        frontend = f"{os.path.basename(tmpdir)}-frontend-1"
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
                compose_status()

                # Make sure we have started the right version
                _validate_container_versions(last_release)

                info("Create test data...")
                docker_cp(str(standalone_dir / "create-testdata.py"), backend, standalone_dest)
                docker_cp(str(standalone_dir / "create-testdata.py"), frontend, standalone_dest)
                _compose_exec("backend", "./create-testdata.py", "--env", "backend")
                _compose_exec("frontend", "./create-testdata.py", "--env", "frontend")

                _compose_exec("backend", "manage", "cache_crls")
                _compose_exec("backend", "manage", "regenerate_ocsp_keys")

                # Write root CA and cert to disk for OpenSSL validation
                ca_subject = "rsa.example.com"  # created by create-testdata.py
                with open("ca.pem", "w", encoding="utf-8") as stream:
                    _manage("backend", "dump_ca", ca_subject, stdout=stream)
                with open("cert.pem", "w", encoding="utf-8") as stream:
                    _manage("frontend", "dump_cert", f"cert.{ca_subject}", stdout=stream)

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

            # Remove legacy Docker Compose configuration file
            docker_compose_yml = Path(tmpdir) / "docker-compose.yml"
            if docker_compose_yml.exists():
                os.remove(docker_compose_yml)
            else:
                # Remind us in the next version that the old config file does not exist anymore.
                info(f"{docker_compose_yml}: File does not exist, you can remove this part of the code.")

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
                compose_status()

                # Make sure we have the new version
                _validate_container_versions(release)

                info("Validate test data...")
                docker_cp(str(validation_script), backend, standalone_dest)
                docker_cp(str(validation_script), frontend, standalone_dest)
                _compose_exec("backend", "./validate-testdata.py", "--env", "backend")
                _compose_exec("frontend", "./validate-testdata.py", "--env", "frontend")

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
                _validate_container_versions(release, env=environ)
                _manage(
                    "backend",
                    "init_ca",
                    "--path-length=1",
                    "Root",
                    "CN=Root",
                    env=environ,
                )
                _manage(
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
                    _compose_exec("certbot", "certbot", "register", stdout=subprocess.DEVNULL, env=environ)
                    _compose_exec(
                        "certbot",
                        "django-ca-test-validation.sh",
                        "http",
                        "http-01.example.com",
                        *extra_certonly_args,
                        env=environ,
                    )
                    ok("Created certificate via a http-01 challenge.")
                    _compose_exec(
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


def _validate_default_version(path: Union[str, "os.PathLike[str]"], release: str) -> int:
    info(f"Validating {path}...")
    if not os.path.exists(path):
        return err(f"{path}: File not found.")
    with open(path, encoding="utf-8") as stream:
        services = yaml.safe_load(stream)["services"]

    errors = 0
    expected_image = f"${{DJANGO_CA_IMAGE:-{config.DOCKER_TAG}}}:${{DJANGO_CA_VERSION:-{release}}}"
    if services["backend"]["image"] != expected_image:
        errors += err(f"{path}: {services['backend']['image']} does not match {expected_image}")
    if services["frontend"]["image"] != expected_image:
        errors += err(f"{path}: {services['frontend']['image']} does not match {expected_image}")

    return errors


def validate_docker_compose_files(release: str) -> int:
    """Validate the state of docker compose files when releasing."""
    errors = 0
    errors += _validate_default_version("compose.yaml", release)
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

    def handle(self, args: argparse.Namespace) -> None:
        if args.docker_prune:
            self.run("docker", "system", "prune", "-af")

        print("Validating docker compose setup...")
        if args.release:
            release = args.release
            docker_tag = self.get_docker_tag(args.release)
        elif args.build:
            release, docker_tag = self.command("build", "docker", "--no-alpine")
        else:
            release = self.django_ca.__version__
            docker_tag = self.get_docker_tag(release)

        info(f"Using {docker_tag} as docker image.")

        errors = 0

        if args.tutorial:
            errors += test_tutorial(release)

        if args.update and errors == 0:
            errors += test_update(release)

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
