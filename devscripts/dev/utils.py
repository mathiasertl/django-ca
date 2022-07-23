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

"""Various utillity functions."""

import datetime
import io
import os
import shlex
import subprocess
import tempfile
import time
from contextlib import contextmanager
from contextlib import redirect_stderr
from contextlib import redirect_stdout

import jinja2
import yaml

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID

from . import config

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader


@contextmanager
def redirect_output():
    """Context manager to redirect both stdout and stderr."""
    out = io.StringIO()
    with redirect_stdout(out), redirect_stderr(out):
        yield out


@contextmanager
def chdir(path):
    """Context manager to temporarily change the working directory to `path`."""
    orig_cwd = os.getcwd()
    try:
        os.chdir(path)
        yield orig_cwd
    finally:
        os.chdir(orig_cwd)


def _waitfor(waitfor, env, context, quiet=True):
    """Helper function to wait until the "waitfor" command succeeds."""
    if not waitfor:
        return

    for command in waitfor:
        waitfor_cmd = shlex.split(env.from_string(command["command"]).render(**context))
        print("+", shlex.join(waitfor_cmd))

        for i in range(0, 15):
            waitfor_proc = run(waitfor_cmd, quiet=quiet, check=False, capture_output=True)
            if waitfor_proc.returncode == 0:
                break
            time.sleep(1)


@contextmanager
def console_include(path, context, quiet=False):
    """Run a console-include from the django_ca_sphinx Sphinx extension."""
    env = jinja2.Environment(autoescape=False, undefined=jinja2.StrictUndefined)

    with open(os.path.join(config.DOC_TEMPLATES_DIR, path), encoding="utf-8") as stream:
        commands = yaml.load(stream, Loader=Loader)["commands"]

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

            stdin = command.get("input")
            stdin_file = command.get("input_file")
            if stdin_file is not None:
                with open(stdin_file, encoding="utf-8") as stream:
                    stdin = stream.read()

            if stdin is not None:
                stdin = env.from_string(stdin).render(**context).encode("utf-8")

            # If a "waitfor" command is defined, don't run actual command until it succeeds
            _waitfor(command.get("waitfor"), env, context)

            run(args, quiet=quiet, capture_output=True, input=stdin)

            for clean in reversed(command.get("clean", [])):
                clean_commands += tmp_clean_commands

        yield
    finally:
        for args in reversed(clean_commands):
            run(args, check=False, capture_output=True, quiet=quiet)


def docker_run(*args, **kwargs):
    """Shortcut for running a docker command."""
    # pylint: disable=subprocess-run-check  # is in kwargs/defaults
    kwargs.setdefault("check", True)
    return subprocess.run(["docker", "run", "--rm"] + list(args), **kwargs)


@contextmanager
def tmpdir(**kwargs):
    """Context manager to temporarily change the working directory to a temporary directory."""

    with tempfile.TemporaryDirectory(**kwargs) as tmpdirname, chdir(tmpdirname):
        yield tmpdirname


def run(args, **kwargs):
    """Shortcut for subprocess.run()."""
    kwargs.setdefault("check", True)
    if not kwargs.pop("quiet", False):
        print("+", shlex.join(args))
    return subprocess.run(args, **kwargs)  # pylint: disable=subprocess-run-check


def create_signed_cert(hostname, signer_privkey, signer_pubkey, priv_out, pub_out, password=None):
    """Create a self-signed cert for the given hostname.

    .. seealso:: https://letsencrypt.org/docs/certificates-for-localhost/
    """

    with open(signer_privkey, "rb") as stream:
        signer_private_key = load_pem_private_key(stream.read(), password)
    with open(signer_pubkey, "rb") as stream:
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

    with open(priv_out, "wb") as stream:
        stream.write(
            private_key.private_bytes(
                encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
            )
        )

    with open(pub_out, "wb") as stream:
        stream.write(certificate.public_bytes(Encoding.PEM))
