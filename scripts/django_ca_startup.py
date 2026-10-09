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

"""Shared startup functions for the container entrypoint scripts.

NOTE: This module must not import anything outside the Python standard library at module level, as it is
executed before Django or any other dependency is set up. Django is only imported (and set up) when a
management command is actually called.
"""

import functools
import os
import secrets
import shlex
import shutil
import socket
import string
import sys
import time
import traceback
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn

#: Default path to the file holding the secret key. Note that the default here matches the default set in the
#: Dockerfile. compose.yaml will override this with a path shared between backend and frontend.
DEFAULT_SECRET_KEY_FILE = "/var/lib/django-ca/certs/ca/shared/secret_key"

#: Characters used for generating a secret key (same as in the shell script).
SECRET_KEY_CHARS = string.ascii_letters + string.digits + string.punctuation


def log(message: str) -> None:
    """Print a message to stdout and flush immediately (output must not be lost on ``exec()``)."""
    print(message, flush=True)


def error(message: str, status: int = 1) -> NoReturn:
    """Print an error message to stderr and exit."""
    print(message, file=sys.stderr, flush=True)
    sys.exit(status)


def getenv(name: str, default: str) -> str:
    """Get an environment variable, using `default` if it is unset *or empty* (like ``${VAR:-default}``)."""
    return os.environ.get(name) or default


def trace(cmd: Sequence[str]) -> None:
    """Print a command before executing it (like ``set -x`` does in the shell)."""
    print(f"+ {shlex.join(cmd)}", file=sys.stderr, flush=True)


def remove_group_other_permissions(path: Path) -> None:
    """Remove any permissions for group and others (like ``chmod go-rwx``)."""
    mode = path.stat().st_mode
    path.chmod(mode & ~0o077 & 0o7777)


def create_secret_key() -> None:
    """Create a secret key file, unless ``DJANGO_CA_SECRET_KEY`` is already set."""
    if os.environ.get("DJANGO_CA_SECRET_KEY"):
        return

    secret_key_file = Path(getenv("DJANGO_CA_SECRET_KEY_FILE", DEFAULT_SECRET_KEY_FILE))

    key_dir = secret_key_file.parent
    if not key_dir.exists():
        key_dir.mkdir(parents=True, exist_ok=True)
        remove_group_other_permissions(key_dir)

    # Wait for another container to create the secret key file
    if os.environ.get("DJANGO_CA_STARTUP_WAIT_FOR_SECRET_KEY_FILE") == "1":
        log(f"{secret_key_file}: Waiting for file to be generated elsewhere...")
        for i in range(1, 6):
            if secret_key_file.exists():
                log(f"{secret_key_file}: File was generated.")
                break
            log(f"{secret_key_file}: Not yet generated, sleeping for {i} seconds...")
            time.sleep(i)

    # Create secret key file if the other container still didn't create it
    if not secret_key_file.exists():
        log(f"{secret_key_file}: Creating secret key...")
        key = "".join(secrets.choice(SECRET_KEY_CHARS) for _ in range(64))

        # Create the file with restrictive permissions right away, so that the key is never readable by
        # others. O_EXCL makes sure that we never overwrite a key that was created concurrently.
        try:
            fd = os.open(secret_key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            log(f"{secret_key_file}: File was generated concurrently.")
        else:
            with os.fdopen(fd, "w") as stream:
                stream.write(key)

    remove_group_other_permissions(secret_key_file)

    # Export DJANGO_CA_SECRET_KEY_FILE so that django-ca itself will pick it up.
    os.environ["DJANGO_CA_SECRET_KEY_FILE"] = str(secret_key_file)


def _parse_connection(conn: str) -> tuple[str, int]:
    """Parse a ``host:port`` string. IPv6 addresses may be given in brackets (e.g. ``[::1]:5432``).

    Like with ``nc``, the port may also be a service name (e.g. ``postgresql``).
    """
    host, sep, port = conn.rpartition(":")
    if not sep or not host or not port:
        error(f"{conn}: Invalid connection, must be in the format host:port.")
    host = host.removeprefix("[").removesuffix("]")

    if port.isdigit():
        return host, int(port)
    try:
        return host, socket.getservbyname(port, "tcp")
    except OSError:
        error(f"{conn}: Unknown service: {port}")


def _can_connect(host: str, port: int, timeout: float = 1.0) -> bool:
    """Test if a TCP connection can be established (like ``nc -z``)."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_for_connections() -> None:
    """Wait for TCP connections given in ``DJANGO_CA_STARTUP_WAIT_FOR_CONNECTIONS`` to become available."""
    connections = os.environ.get("DJANGO_CA_STARTUP_WAIT_FOR_CONNECTIONS", "").split()
    for conn in connections:
        host, port = _parse_connection(conn)
        while not _can_connect(host, port):
            log(f"Wait for {host} {port}...")
            time.sleep(0.1)  # wait for 1/10 of the second before check again


@functools.cache
def _setup_django() -> None:
    """Set up Django (only once, and only when a management command is actually called).

    This mirrors what ``manage.py`` does: The current working directory (where ``manage.py`` is located) is
    added to the Python path and ``DJANGO_SETTINGS_MODULE`` defaults to ``ca.settings``.

    NOTE: Django is imported here (and not at module level) so that no external dependencies are imported
    unless a management command is actually called.
    """
    sys.path.insert(0, os.getcwd())
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ca.settings")

    import django  # noqa: PLC0415  # pylint: disable=import-outside-toplevel

    django.setup()


def _close_db_connections() -> None:
    """Close database connections, but only if Django was set up in the first place.

    Connections must be closed before calling ``fork()`` (so that parent and child do not share a connection)
    and before calling ``exec()`` (so that connections are terminated cleanly).
    """
    if _setup_django.cache_info().currsize == 0:
        return

    from django.db import connections  # noqa: PLC0415  # pylint: disable=import-outside-toplevel

    connections.close_all()


def _call_command(name: str, *args: str) -> None:
    """Call a management command in the current process. Errors cause the process to exit."""
    _setup_django()

    # pylint: disable-next=import-outside-toplevel
    from django.core.management import CommandError, call_command  # noqa: PLC0415

    try:
        call_command(name, *args)
    except CommandError as ex:  # also includes SystemCheckError
        error(f"{type(ex).__name__}: {ex}", status=ex.returncode)


def _call_command_in_background(name: str, *args: str) -> None:
    """Call a management command in a forked child process (like ``&`` in the shell).

    The parent does not wait for the child, and errors in the child are ignored (but printed to stderr).
    Since the parent will ``exec()`` into the main process (keeping the same PID), the child continues to run
    in parallel to the main process.
    """
    _setup_django()  # set up Django before forking, so that it is only done once
    _close_db_connections()
    sys.stdout.flush()  # flush buffers so that the child does not output any buffered data a second time
    sys.stderr.flush()

    if os.fork() != 0:  # parent process
        return

    status = 1
    try:
        _call_command(name, *args)
        status = 0
    except SystemExit as ex:
        status = ex.code if isinstance(ex.code, int) else 1
    except Exception:  # noqa: BLE001  # pylint: disable=broad-exception-caught
        traceback.print_exc()  # print traceback here, as the exception never propagates beyond os._exit()
    finally:
        _close_db_connections()
        sys.stdout.flush()
        sys.stderr.flush()
        # Use os._exit() so that the child never returns into the parents code path (or runs atexit handlers).
        os._exit(status)  # pylint: disable=protected-access


def run_manage_commands() -> None:
    """Run management commands required at startup (unless disabled via environment variables)."""
    if os.environ.get("DJANGO_CA_STARTUP_CHECK") != "0":
        _call_command("check", "--deploy")

    if os.environ.get("DJANGO_CA_STARTUP_MIGRATE") != "0":
        log("Running database migrations...")
        _call_command("migrate", "--noinput")
    if os.environ.get("DJANGO_CA_STARTUP_GENERATE_CRLS") != "0":
        log("Caching CRLs...")
        _call_command_in_background("generate_crls")
    if os.environ.get("DJANGO_CA_STARTUP_GENERATE_OCSP_KEYS") != "0":
        log("Generating OCSP keys...")
        _call_command_in_background("generate_ocsp_keys")
    if os.environ.get("DJANGO_CA_STARTUP_COLLECTSTATIC") != "0":
        log("Collecting static files...")
        _call_command_in_background("collectstatic", "--no-input")


def startup() -> None:
    """Run all common startup functions."""
    create_secret_key()
    wait_for_connections()
    run_manage_commands()


def exec_command(cmd: Sequence[str]) -> NoReturn:
    """Replace the current process with the given command (like ``exec`` in the shell)."""
    _close_db_connections()
    sys.stdout.flush()  # flush first, so that any buffered output appears before the trace
    trace(cmd)
    sys.stderr.flush()
    try:
        os.execvp(cmd[0], list(cmd))
    except FileNotFoundError:
        error(f"{cmd[0]}: command not found", status=127)


def copy_file(src: Path, dest: Path, preserve: bool = True) -> None:
    """Copy a file, removing the destination if it cannot be opened (like ``cp -f``).

    If `preserve` is ``True``, metadata (mode, timestamps) is preserved (like ``cp -p``).
    """
    if dest.is_dir():
        dest = dest / src.name
    copy_function = shutil.copy2 if preserve else shutil.copy
    try:
        copy_function(src, dest)
    except PermissionError:
        dest.unlink(missing_ok=True)
        copy_function(src, dest)


def _copy_file_no_preserve(src: str, dest: str) -> None:
    """Copy function for :py:func:`shutil.copytree` (like ``cp -f`` without ``-p``)."""
    copy_file(Path(src), Path(dest), preserve=False)


def copy_tree_contents(src: Path, dest: Path) -> None:
    """Recursively copy all non-hidden entries in `src` to `dest` (like ``cp -rf src/* dest/``)."""
    entries = sorted(entry for entry in src.iterdir() if not entry.name.startswith("."))
    if not entries:
        error(f"cp: cannot stat '{src}/*': No such file or directory")

    for entry in entries:
        if entry.is_dir():
            shutil.copytree(
                entry,
                dest / entry.name,
                symlinks=True,
                copy_function=_copy_file_no_preserve,
                dirs_exist_ok=True,
            )
        else:
            copy_file(entry, dest, preserve=False)


def copy_glob(src: Path, pattern: str, dest: Path) -> None:
    """Copy files matching `pattern` in `src` to `dest` (like ``cp -pf src/pattern dest/``)."""
    matches = sorted(path for path in src.glob(pattern) if not path.name.startswith("."))
    if not matches:
        error(f"cp: cannot stat '{src / pattern}': No such file or directory")
    for path in matches:
        copy_file(path, dest)
