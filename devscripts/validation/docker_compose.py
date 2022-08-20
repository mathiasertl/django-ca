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
import re
import shutil
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

import requests

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509.oid import ExtensionOID

# pylint: disable=no-name-in-module  # false positive due to dev.py
from dev import config
from dev import utils
from dev.out import err
from dev.out import info
from dev.out import ok
from dev.tutorial import start_tutorial

# pylint: enable=no-name-in-module


@contextmanager
def _compose_up(quiet, remove_volumes=True, **kwargs):
    try:
        utils.run(["docker-compose", "up", "-d"], capture_output=True, quiet=quiet, **kwargs)
        yield
    finally:
        down = ["docker-compose", "down"]
        if remove_volumes is True:
            down.append("-v")
        utils.run(down, capture_output=True, quiet=quiet)


def _compose_exec(*args, **kwargs):
    cmd = ["docker-compose", "exec"] + kwargs.pop("compose_args", []) + list(args)
    return utils.run(cmd, **kwargs)


def _manage(container, *args, **kwargs):
    return _compose_exec(container, "manage", *args, **kwargs)


def _sign_cert(container, ca, csr, quiet):
    subject = f"signed-in-{container}.{ca.lower()}.example.com"

    _manage(
        container,
        "sign_cert",
        f"--ca={ca}",
        f"--subject=/CN={subject}",
        quiet=quiet,
        capture_output=True,
        input=csr,
        text=True,
        compose_args=["-T"],
    )
    return subject


def _run_py(container, code, **kwargs):
    return _manage(container, "shell", "-c", code, capture_output=True, text=True, **kwargs).stdout


def _openssl_verify(ca_file, cert_file, quiet):
    return utils.run(
        ["openssl", "verify", "-CAfile", ca_file, "-crl_download", "-crl_check", cert_file],
        quiet=quiet,
        capture_output=True,
        text=True,
    )


def _openssl_ocsp(ca_file, cert_file, url, quiet):
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
        quiet=quiet,
        capture_output=True,
        text=True,
    )


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


def _validate_crl_ocsp(ca_file, cert_file, cert_subject, quiet):
    """Test OpenSSL CRL and OCSP validation.

    This only tests the CRL for the root CA. It's the test suites job to test the views in more detail.
    """

    with open(cert_file, "rb") as stream:
        cert = x509.load_pem_x509_certificate(stream.read())

    # Get the OCSP url from the certificate
    aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    ocsp_ad = [ad for ad in aia if ad.access_method == AuthorityInformationAccessOID.OCSP][0]
    ocsp_url = ocsp_ad.access_location.value

    _openssl_verify(ca_file, cert_file, quiet=quiet)
    _openssl_ocsp(ca_file, cert_file, ocsp_url, quiet=quiet)

    _manage("frontend", "revoke_cert", cert_subject)

    # Still okay, because CRL is cached
    _openssl_verify("root.pem", cert_file, quiet=quiet)
    _manage("frontend", "cache_crls")
    time.sleep(1)  # give celery task some time

    # "openssl ocsp" always returns 0 if it retrieves a valid OCSP response, even if the cert is revoked
    proc = _openssl_ocsp(ca_file, cert_file, ocsp_url, quiet=quiet)
    assert "Cert Status: revoked" in proc.stdout

    # Make sure that CRL validation fails now too
    try:
        _openssl_verify(ca_file, cert_file, quiet=quiet)
    except subprocess.CalledProcessError as ex:
        assert "verification failed" in ex.stdout
    else:
        raise RuntimeError("Certificate is not revoked in CRL.")

    ok("CRL and OCSP validation works.")


def _sign_certificates(csr, quiet):
    # Sign some certs in the backend
    cert_subject = _sign_cert("backend", "Root", csr, quiet=quiet)
    _sign_cert("backend", "Intermediate", csr, quiet=quiet)

    # Sign certs in the frontend (only intermediate works, root was created in backend)
    _sign_cert("frontend", "Intermediate", csr, quiet=quiet)

    try:
        _sign_cert("frontend", "Root", csr, quiet=quiet)
    except subprocess.CalledProcessError as ex:
        assert re.search(r"Root:.*Private key does not exist\.", ex.stderr)
    else:
        raise RuntimeError("Was able to sign root cert in frontend.")

    return cert_subject


def test_update(release, quiet):
    print("Validating docker-compose update...")
    errors = 0
    # Get the last release, so we can update
    last_release = utils.get_previous_release(current_release=release)
    root_dir = Path(config.ROOT_DIR)
    with tempfile.TemporaryDirectory() as tmpdir:
        info(f"Creating temporary clone in {tmpdir}")
        last_release_dest = utils.git_archive(last_release, tmpdir)
        shutil.copy(last_release_dest / "docker-compose.yml", tmpdir)

        with utils.chdir(tmpdir):
            # Add a very basic .env file
            with open(".env", "w") as stream:
                stream.write(
                    """DJANGO_CA_CA_DEFAULT_HOSTNAME=localhost
DJANGO_CA_CA_ENABLE_ACME=true
POSTGRES_PASSWORD=mysecretpassword
"""
                )

            # Start previous version
            with _compose_up(
                quiet=quiet, remove_volumes=False, env=dict(os.environ, DJANGO_CA_VERSION=last_release)
            ):
                # Make sure we have started the right version
                _validate_container_versions(last_release, quiet)

                tmpdirname = os.path.basename(tmpdir)
                utils.run(
                    [
                        "docker",
                        "cp",
                        str(last_release_dest / "devscripts" / "create-testdata.py"),
                        f"{tmpdirname}_backend_1:/usr/src/django-ca/ca/",
                    ],
                    quiet=quiet,
                )
                utils.run(
                    [
                        "docker",
                        "cp",
                        str(last_release_dest / "devscripts" / "create-testdata.py"),
                        f"{tmpdirname}_frontend_1:/usr/src/django-ca/ca/",
                    ],
                    quiet=quiet,
                )

                _compose_exec("backend", "./create-testdata.py", "--env", "backend", quiet=quiet)
                _compose_exec("frontend", "./create-testdata.py", "--env", "frontend", quiet=quiet)

            # copy new docker-compose file
            shutil.copy(root_dir / "docker-compose.yml", tmpdir)

            with _compose_up(quiet=quiet, env=dict(os.environ, DJANGO_CA_VERSION="latest")):
                # _validate_container_versions(release, quiet)
                utils.run(
                    [
                        "docker",
                        "cp",
                        str(root_dir / "devscripts" / "validate-testdata.py"),
                        f"{tmpdirname}_backend_1:/usr/src/django-ca/ca/",
                    ],
                    quiet=quiet,
                )
                utils.run(
                    [
                        "docker",
                        "cp",
                        str(root_dir / "devscripts" / "validate-testdata.py"),
                        f"{tmpdirname}_frontend_1:/usr/src/django-ca/ca/",
                    ],
                    quiet=quiet,
                )

                _compose_exec("backend", "./validate-testdata.py", "--env", "backend", quiet=quiet)
                _compose_exec("frontend", "./validate-testdata.py", "--env", "frontend", quiet=quiet)

    return errors


def validate_docker_compose(release=None, quiet=False):  # pylint: disable=too-many-statements,too-many-locals
    """Validate the docker-compose file (and the tutorial)."""
    print("Validating docker-compose setup...")
    errors = 0

    docker_compose_yml = os.path.join(config.ROOT_DIR, "docker-compose.yml")
    if release:
        docker_compose_yml = os.path.join(config.DOCS_DIR, "source", "_files", release, "docker-compose.yml")

    if not os.path.exists(docker_compose_yml):
        return err(f"{docker_compose_yml}: File not found.")

    # Calculate some static paths
    ca_key = config.FIXTURES_DIR / "root.key"
    ca_pub = config.FIXTURES_DIR / "root.pub"
    csr_path = config.FIXTURES_DIR / "root-cert.csr"

    # Read CSR so we can pass it in context
    with open(csr_path, encoding="utf-8") as stream:
        csr = stream.read()

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
        "csr": csr,
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

        utils.create_signed_cert(_ca_default_hostname, ca_key, ca_pub, archive_privkey, archive_fullchain)

        (live_path / "privkey.pem").symlink_to(os.path.relpath(archive_privkey, live_path))
        (live_path / "fullchain.pem").symlink_to(os.path.relpath(archive_fullchain, live_path))

        with tut.run("dhparam.yaml"), tut.run("docker-compose-up.yaml"), tut.run("verify-setup.yaml"):
            ok("Containers seem to have started properly.")

            # Check that we didn't forget any migrations
            _manage("backend", "makemigrations", "--check", quiet=quiet, capture_output=True)
            _manage("frontend", "makemigrations", "--check", quiet=quiet, capture_output=True)

            # Validate that the container versions match the expected version
            errors += _validate_container_versions(release, quiet)

            # Validate that the secret keys match
            errors += _validate_secret_key(quiet)

            # Test that HTTPS connection and admin interface is working:
            resp = requests.get("https://localhost/admin/", verify=ca_pub)
            resp.raise_for_status()

            # Test static files
            resp = requests.get("https://localhost/static/admin/css/base.css", verify=ca_pub)
            resp.raise_for_status()

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
                cert_subject = _sign_certificates(csr, quiet=quiet)

                certs = _manage("frontend", "list_certs", capture_output=True, text=True).stdout.splitlines()
                assert len(certs) == 5, f"Found {len(certs)} certs instead of 5."
                ok("Signed certificates.")

                # Write root CA and cert to disk for OpenSSL validation
                with open("root.pem", "w", encoding="utf-8") as stream:
                    _manage("backend", "dump_ca", "Root", stdout=stream)
                with open(f"{cert_subject}.pem", "w", encoding="utf-8") as stream:
                    _manage("frontend", "dump_cert", cert_subject, stdout=stream)

                # Test CRL and OCSP validation
                _validate_crl_ocsp("root.pem", f"{cert_subject}.pem", cert_subject, quiet=quiet)

                utils.run(["docker-compose", "down"], capture_output=True, quiet=quiet)
                utils.run(["docker-compose", "up", "-d"], capture_output=True, quiet=quiet)
                ok("Restarted docker containers.")

                # Finally some manual testing
                info(
                    f"""Test admin interface at

    * URL: https://{_ca_default_hostname}/admin
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
                cert_subject = _sign_certificates(csr, quiet=quiet)

    errors += test_update(release, quiet=quiet)

    return errors
