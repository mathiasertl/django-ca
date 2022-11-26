# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca.  If not,
# see <http://www.gnu.org/licenses/>.

"""Command subclasses and argparse helpers for django-ca."""

import abc
import argparse
import io
import sys
import typing
from datetime import datetime, timedelta

from cryptography import x509

from django.core.management.base import BaseCommand as _BaseCommand
from django.core.management.base import CommandError, CommandParser, OutputWrapper
from django.utils import timezone

from .. import ca_settings
from ..models import CertificateAuthority
from ..profiles import Profile
from ..utils import NAME_OID_MAPPINGS
from . import actions, mixins


class BinaryOutputWrapper(OutputWrapper):
    """An output wrapper that allows you to write binary data."""

    ending: bytes  # type: ignore[assignment]
    _out: typing.BinaryIO

    def __init__(self, out: typing.BinaryIO, ending: bytes = b"\n") -> None:
        super().__init__(out, ending=ending)  # type: ignore[arg-type]

    def write(  # type: ignore[override]
        self,
        msg: typing.Union[str, bytes] = b"",
        style_func: typing.Optional[typing.Callable[..., typing.Any]] = None,
        ending: typing.Optional[bytes] = None,
    ) -> None:
        if ending is None:
            ending = self.ending

        if isinstance(msg, str):
            msg = msg.encode("utf-8")
        if ending and not msg.endswith(ending):
            msg += ending

        self._out.write(msg)


class BinaryCommand(mixins.ArgumentsMixin, _BaseCommand, metaclass=abc.ABCMeta):
    """A :py:class:`~django:django.core.management.BaseCommand` that supports binary output."""

    stdout: BinaryOutputWrapper
    stderr: BinaryOutputWrapper

    def __init__(
        self,
        stdout: typing.Optional[io.BytesIO] = None,
        stderr: typing.Optional[io.BytesIO] = None,
        no_color: bool = True,
        force_color: bool = False,
    ) -> None:
        # BaseCommand error handling is not suitable and sets stdout/stderr redundantly:
        # pylint: disable=super-init-not-called

        self.stdout = BinaryOutputWrapper(stdout or sys.stdout.buffer)
        # TODO: we set stdout below?!
        self.stderr = BinaryOutputWrapper(stdout or sys.stdout.buffer)

    def execute(self, *args: typing.Any, **options: typing.Any) -> None:
        if options.get("force_color"):
            raise CommandError("This command does not support color output.")

        if options.get("stdout"):  # pragma: no branch
            self.stdout = BinaryOutputWrapper(options.pop("stdout"))
        if options.get("stderr"):  # pragma: no branch
            self.stderr = BinaryOutputWrapper(options.pop("stderr"))
        options["no_color"] = True

        super().execute(*args, **options)

    def dump(self, path: str, data: bytes) -> None:
        """Dump `data` to `path` (``-`` means stdout)."""

        if path == "-":
            self.stdout.write(data, ending=b"")
        else:
            try:
                with open(path, "wb") as stream:
                    stream.write(data)
            except IOError as ex:
                raise CommandError(ex) from ex


class BaseCommand(mixins.ArgumentsMixin, _BaseCommand, metaclass=abc.ABCMeta):
    """Base class for most/all management commands."""

    @property
    def valid_subject_keys(self) -> str:
        """Return human-readable enumeration of valid subject keys (CN/...)."""
        fields = [f'"{f}"' for f in NAME_OID_MAPPINGS]
        return f"{', '.join(fields[:-1])} and {fields[-1]}"

    def add_subject(
        self,
        parser: argparse._ActionsContainer,
        arg: str = "subject",
        metavar: typing.Optional[str] = None,
        help_text: typing.Optional[str] = None,
    ) -> None:
        """Add subject option."""
        parser.add_argument(arg, action=actions.NameAction, metavar=metavar, help=help_text)

    def add_ecc_curve(self, parser: CommandParser) -> None:
        """Add --ecc-curve option."""
        default = ca_settings.CA_DEFAULT_ECC_CURVE()
        parser.add_argument(
            "--ecc-curve",
            metavar="CURVE",
            action=actions.KeyCurveAction,
            default=default,
            help=f"Elliptic Curve used for ECC keys (default: {default.name}).",
        )

    def add_key_size(self, parser: CommandParser) -> None:
        """Add --key-size option (2048, 4096, ...)."""
        parser.add_argument(
            "--key-size",
            action=actions.KeySizeAction,
            default=ca_settings.CA_DEFAULT_KEY_SIZE,
            help="Key size for the private key (default: %(default)s).",
        )

    def add_key_type(self, parser: CommandParser) -> None:
        """Add --key-type option (type of private key - RSA/DSA/ECC/EdDSA)."""
        parser.add_argument(
            "--key-type",
            choices=["RSA", "DSA", "ECC", "EdDSA"],
            default="RSA",
            help="Key type for the private key (default: %(default)s).",
        )

    def add_profile(self, parser: CommandParser, help_text: str) -> None:
        """Add profile-related options."""
        group = parser.add_argument_group("profiles", help_text)
        group = group.add_mutually_exclusive_group()
        for name, profile in ca_settings.CA_PROFILES.items():
            group.add_argument(
                f"--{name}",
                action="store_const",
                const=name,
                dest="profile",
                help=profile.get("description", ""),
            )


class BaseSignCommand(BaseCommand):  # pylint: disable=abstract-method; is a base class
    """Base class for commands signing certificates (sign_cert, resign_cert)."""

    add_extensions_help = ""  # concrete classes should set this
    sign_extensions: typing.Tuple[typing.Type[x509.ExtensionType], ...] = (
        x509.ExtendedKeyUsage,
        x509.KeyUsage,
        x509.SubjectAlternativeName,
        x509.TLSFeature,
    )
    subject_help = ""  # concrete classes should set this

    def add_base_args(self, parser: CommandParser, no_default_ca: bool = False) -> None:
        """Add common arguments for signing certificates."""
        self.add_subject_group(parser)
        self.add_algorithm(parser)
        self.add_ca(parser, no_default=no_default_ca)
        self.add_password(parser)
        self.add_extensions(parser)

        parser.add_argument(
            "--expires",
            action=actions.ExpiresAction,
            help=f"Sign the certificate for DAYS days (default: {ca_settings.CA_DEFAULT_EXPIRES})",
        )
        parser.add_argument(
            "--alt",
            metavar="DOMAIN",
            action=actions.AlternativeNameAction,
            extension_type=x509.SubjectAlternativeName,
            help="Add a subjectAltName to the certificate (may be given multiple times)",
        )
        parser.add_argument(
            "--watch",
            metavar="EMAIL",
            action="append",
            default=[],
            help="Email EMAIL when this certificate expires (may be given multiple times)",
        )
        parser.add_argument(
            "--out", metavar="FILE", help="Save signed certificate to FILE. If omitted, print to stdout."
        )

    def add_subject_group(self, parser: CommandParser) -> None:
        """Add argument for a subject."""

        group = parser.add_argument_group("Certificate subject", self.subject_help)

        # NOTE: Don't set the default value here because it would mask the user not setting anything at all.
        self.add_subject(
            group,
            arg="--subject",
            metavar="/key1=value1/key2=value2/...",
            help_text=f"""Valid keys are {self.valid_subject_keys}. Pass an empty value (e.g. "/C=/ST=...")
            to remove a field from the subject.""",
        )

    def add_extensions(self, parser: CommandParser) -> None:
        """Add arguments for x509 extensions."""
        group = parser.add_argument_group("X509 v3 certificate extensions", self.add_extensions_help)
        group.add_argument(
            "--key-usage",
            metavar="VALUES",
            action=actions.KeyUsageAction,
            help='The keyUsage extension, e.g. "critical,keyCertSign".',
        )
        group.add_argument(
            "--ext-key-usage",
            metavar="VALUES",
            action=actions.ExtendedKeyUsageAction,
            help='The extendedKeyUsage extension, e.g. "serverAuth,clientAuth".',
        )
        group.add_argument(
            "--tls-feature",
            metavar="VALUES",
            action=actions.TLSFeatureAction,
            help="TLS Feature extensions.",
        )

    def test_options(  # pylint: disable=unused-argument
        self,
        ca: CertificateAuthority,
        expires: typing.Optional[typing.Union[datetime, timedelta]],
        password: typing.Optional[bytes],
        profile: Profile,
        **options: typing.Any,
    ) -> None:
        """Additional tests for validity of some options."""

        expires = profile.get_expires(expires)

        if ca.expires < expires:
            max_days = (ca.expires - timezone.now()).days
            raise CommandError(
                f"Certificate would outlive CA, maximum expiry for this CA is {max_days} days."
            )

        # See if we can work with the private key
        self.test_private_key(ca, password)
