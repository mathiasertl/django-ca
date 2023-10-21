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

"""Various utility functions."""

import datetime
import io
import os
import random
import shlex
import string
import subprocess
import tempfile
import time
import typing
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, Optional, Sequence, Union

import yaml

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from cryptography.x509.oid import NameOID

from devscripts import config

if typing.TYPE_CHECKING:
    import jinja2


@contextmanager
def redirect_output() -> Iterator[io.StringIO]:
    """Context manager to redirect both stdout and stderr."""
    out = io.StringIO()
    with redirect_stdout(out), redirect_stderr(out):
        yield out


@contextmanager
def chdir(path: Union[str, "os.PathLike[str]"]) -> Iterator[str]:
    """Context manager to temporarily change the working directory to `path`."""
    orig_cwd = os.getcwd()
    try:
        os.chdir(path)
        yield orig_cwd
    finally:
        os.chdir(orig_cwd)


def _wait_for(
    wait_for: Iterable[Dict[str, Any]],
    jinja_env: "jinja2.Environment",
    context: Dict[str, Any],
    **kwargs: Any,
) -> None:
    """Helper function to wait until the "wait_for" command succeeds."""
    if not wait_for:
        return

    for command in wait_for:
        wait_for_cmd = shlex.split(jinja_env.from_string(command["command"]).render(**context))

        for i in range(0, 15):
            wait_for_proc = run(wait_for_cmd, check=False, **kwargs)
            if wait_for_proc.returncode == 0:
                break
            time.sleep(1)


@contextmanager
def console_include(path: str, context: Dict[str, Any]) -> Iterator[None]:
    """Run a console-include from the django_ca_sphinx Sphinx extension."""
    # PYLINT NOTE: lazy import so that just importing this module has no external dependencies
    import jinja2  # pylint: disable=import-outside-toplevel

    env = jinja2.Environment(autoescape=False, undefined=jinja2.StrictUndefined)

    with open(config.DOC_TEMPLATES_DIR / path, encoding="utf-8") as stream:
        commands = yaml.safe_load(stream)["commands"]

    clean_commands = []
    context.setdefault("pwd", os.getcwd())

    try:
        for command in commands:
            command_str = command.get("run", command["command"])

            # Render commands early so that we fail as soon as possible if there is an error in the templates
            args = shlex.split(env.from_string(command_str).render(**context))
            tmp_clean_commands = [
                shlex.split(env.from_string(cmd).render(**context))
                for cmd in reversed(command.get("clean", []))
            ]

            for cmd in command.get("before_command", []):
                run(shlex.split(env.from_string(cmd).render(**context)))

            stdin = command.get("input")
            stdin_file = command.get("input_file")
            if stdin_file is not None:
                with open(stdin_file, encoding="utf-8") as stream:
                    stdin = stream.read()

            if stdin is not None:
                stdin = env.from_string(stdin).render(**context).encode("utf-8")

            # add shell environment variables
            shell_env = command.get("env")
            if shell_env is not None:
                shell_env = {k: env.from_string(v).render(**context) for k, v in shell_env.items()}
                shell_env = dict(os.environ, **shell_env)

            # If a "wait_for" command is defined, don't run actual command until it succeeds
            _wait_for(command.get("wait_for"), env, context, env=shell_env)

            run(args, input=stdin, env=shell_env)

            for cmd in command.get("after_command", []):
                run(shlex.split(env.from_string(cmd).render(**context)))

            clean_commands += tmp_clean_commands

        yield
    finally:
        for args in reversed(clean_commands):
            run(args, check=False)


def get_previous_release(current_release: Optional[str] = None) -> str:
    """Get the previous release based on git tags.

    This function returns the name at the last tag that is a valid semantic version. Pre-release or build tags
    are automatically excluded.  If `current_release` is given, it will be excluded from the list.
    """
    # PYLINT NOTE: lazy import so that just importing this module has no external dependencies
    import semantic_version  # pylint: disable=import-outside-toplevel
    from git import Repo  # pylint: disable=import-outside-toplevel

    repo = Repo(config.ROOT_DIR)
    tags = [tag.name for tag in repo.tags]

    # Exclude release tag if we are on a release
    if current_release is not None:
        tags = [tag for tag in tags if tag != current_release]

    parsed_tags = []
    for tag in tags:
        try:
            parsed_tags.append(semantic_version.Version(tag))
        except ValueError:
            continue

    parsed_tags = sorted([tag for tag in parsed_tags if not tag.prerelease and not tag.build])
    return str(parsed_tags[-1])


def docker_run(*args: str, **kwargs: Any) -> "subprocess.CompletedProcess[Any]":
    """Shortcut for running a docker command."""
    return run(["docker", "run", "--rm"] + list(args), **kwargs)


def docker_exec(container: str, *args: str) -> "subprocess.CompletedProcess[Any]":
    """Run a command in the given Docker container."""
    return run(["docker", "exec", container] + list(args))


@contextmanager
def tmpdir() -> Iterator[str]:
    """Context manager to temporarily change the working directory to a temporary directory."""
    with tempfile.TemporaryDirectory() as tmp_directory, chdir(tmp_directory):
        yield tmp_directory


def run(args: Sequence[str], **kwargs: Any) -> "subprocess.CompletedProcess[Any]":
    """Shortcut for subprocess.run()."""
    kwargs.setdefault("check", True)
    if config.SHOW_COMMANDS:
        print("+", shlex.join(args))
    if not config.SHOW_COMMAND_OUTPUT and not kwargs.get("capture_output"):
        kwargs.setdefault("stdout", subprocess.DEVNULL)
        kwargs.setdefault("stderr", subprocess.DEVNULL)
    return subprocess.run(args, **kwargs)  # pylint: disable=subprocess-run-check


def git_archive(ref: str, destination: str) -> Path:
    """Export the git repository to `django-ca-{ref}/` in the given destination directory.

    `ref` may be any valid git reference, usually a git tag.
    """
    # Add a random suffix to the export destination to improve build isolation (e.g. Docker Compose will use
    # that directory name as a name for Docker images/containers).
    random_suffix = "".join(random.choice(string.ascii_lowercase) for i in range(12))
    destination = os.path.join(destination, f"django-ca-{ref}-{random_suffix}")

    if not os.path.exists(destination):
        os.makedirs(destination)

    with subprocess.Popen(["git", "archive", ref], stdout=subprocess.PIPE) as git_archive_cmd:
        with subprocess.Popen(["tar", "-x", "-C", destination], stdin=git_archive_cmd.stdout) as tar:
            # TYPEHINT NOTE: stdout is not None b/c of stdout=subprocess.PIPE
            stdout = typing.cast(typing.IO[bytes], git_archive_cmd.stdout)
            stdout.close()
            tar.communicate()
    return Path(destination)


def create_signed_cert(
    hostname: str,
    signer_private_key_path: Union[str, "os.PathLike[str]"],
    signer_public_key_path: Union[str, "os.PathLike[str]"],
    private_key_path: Union[str, "os.PathLike[str]"],
    public_key_path: Union[str, "os.PathLike[str]"],
    password: Optional[bytes] = None,
) -> None:
    """Create a self-signed cert for the given hostname.

    .. seealso:: https://letsencrypt.org/docs/certificates-for-localhost/
    """
    with open(signer_private_key_path, "rb") as stream:
        signer_private_key = typing.cast(
            CertificateIssuerPrivateKeyTypes, load_pem_private_key(stream.read(), password)
        )
    with open(signer_public_key_path, "rb") as stream:
        signer_public_key = x509.load_pem_x509_certificate(stream.read())

    one_day = datetime.timedelta(1, 0, 0)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
    builder = builder.issuer_name(signer_public_key.subject)

    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)

    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    certificate = builder.sign(private_key=signer_private_key, algorithm=hashes.SHA256())

    with open(private_key_path, "wb") as stream:
        stream.write(
            private_key.private_bytes(
                encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
            )
        )

    with open(public_key_path, "wb") as stream:
        stream.write(certificate.public_bytes(Encoding.PEM))
