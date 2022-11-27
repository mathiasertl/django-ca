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

"""Management command to create a certificate authority.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

import os
import pathlib
import typing
from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from django.core.management.base import CommandError, CommandParser
from django.utils import timezone

from ... import ca_settings
from ...constants import EXTENSION_KEYS
from ...models import CertificateAuthority
from ...tasks import cache_crl, generate_ocsp_key, run_task
from ...typehints import ParsableKeyType
from ...utils import parse_general_name, sort_name
from ..actions import ExpiresAction, MultipleURLAction, NameAction, PasswordAction, URLAction
from ..base import BaseCommand
from ..mixins import CertificateAuthorityDetailMixin


class Command(CertificateAuthorityDetailMixin, BaseCommand):
    """Implement :command:`manage.py init_ca`."""

    help = "Create a certificate authority."

    def add_arguments(self, parser: CommandParser) -> None:
        self.add_general_args(parser)
        self.add_algorithm(parser)

        self.add_key_type(parser)
        self.add_key_size(parser)
        self.add_ecc_curve(parser)

        parser.add_argument(
            "--expires",
            metavar="DAYS",
            action=ExpiresAction,
            default=timedelta(365 * 10),
            help="CA certificate expires in DAYS days (default: %(default)s).",
        )
        self.add_ca(
            parser,
            "--parent",
            no_default=True,
            help_text="Make the CA an intermediate CA of the named CA. By default, this is a new root CA.",
        )
        parser.add_argument("name", help="Human-readable name of the CA")
        parser.add_argument(
            "subject",
            action=NameAction,
            help='The subject of the CA in the format "/key1=value1/key2=value2/...", requires at least a'
            "CommonName to be present (/CN=...).",
        )
        self.add_password(
            parser,
            help_text="Optional password used to encrypt the private key. If no argument is passed, "
            "you will be prompted.",
        )
        parser.add_argument(
            "--path",
            type=pathlib.PurePath,
            help="Path where to store Certificate Authorities (relative to CA_DIR).",
        )
        parser.add_argument(
            "--parent-password",
            nargs="?",
            action=PasswordAction,
            metavar="PASSWORD",
            prompt="Password for parent CA: ",
            help="Password for the private key of any parent CA.",
        )

        group = parser.add_argument_group(
            "Default hostname",
            f"""The default hostname is used to compute default URLs for services like OCSP. The hostname is
            usually configured in your settings (current setting: {ca_settings.CA_DEFAULT_HOSTNAME}), but you
            can override that value here. The value must be just the hostname and optionally a port, *without*
            a protocol, e.g.  "ca.example.com" or "ca.example.com:8000".""",
        )
        group = group.add_mutually_exclusive_group()
        group.add_argument(
            "--default-hostname",
            metavar="HOSTNAME",
            help="Override the the default hostname configured in your settings.",
        )
        group.add_argument(
            "--no-default-hostname",
            dest="default_hostname",
            action="store_false",
            help="Disable any default hostname configured in your settings.",
        )

        self.add_acme_group(parser)

        group = parser.add_argument_group(
            "pathlen attribute",
            """Maximum number of CAs that can appear below this one. A pathlen of zero (the default) means it
            can only be used to sign end user certificates and not further CAs.""",
        )
        group = group.add_mutually_exclusive_group()
        group.add_argument(
            "--pathlen", default=0, type=int, help="Maximum number of sublevel CAs (default: %(default)s)."
        )
        group.add_argument(
            "--no-pathlen",
            action="store_const",
            const=None,
            dest="pathlen",
            help="Do not add a pathlen attribute.",
        )

        group = parser.add_argument_group(
            "X509 v3 certificate extensions for CA",
            """Extensions added to the certificate authority itself. These options cannot be changed without
            creating a new authority.""",
        )
        group.add_argument(
            "--ca-crl-url",
            action=MultipleURLAction,
            help="URL to a certificate revokation list. Can be given multiple times.",
        )
        group.add_argument("--ca-ocsp-url", metavar="URL", action=URLAction, help="URL of an OCSP responder.")
        group.add_argument(
            "--ca-issuer-url",
            metavar="URL",
            action=URLAction,
            help="URL to the certificate of your CA (in DER format).",
        )

        nc_group = parser.add_argument_group(
            "Name Constraints", "Add name constraints to the CA, limiting what certificates this CA can sign."
        )
        nc_group.add_argument(
            "--permit-name",
            metavar="NAME",
            action="append",
            type=parse_general_name,
            help="Add NAME to the permitted-subtree.",
        )
        nc_group.add_argument(
            "--exclude-name",
            metavar="NAME",
            action="append",
            type=parse_general_name,
            help="Add NAME to the excluded-subtree.",
        )

        self.add_ca_args(parser)

    def handle(  # pylint: disable=too-many-arguments,too-many-locals
        self,
        name: str,
        subject: x509.Name,
        parent: typing.Optional[CertificateAuthority],
        expires: timedelta,
        key_size: int,
        key_type: ParsableKeyType,
        ecc_curve: typing.Optional[ec.EllipticCurve],
        algorithm: hashes.HashAlgorithm,
        pathlen: typing.Optional[int],
        password: typing.Optional[bytes],
        parent_password: typing.Optional[bytes],
        crl_url: typing.List[str],
        ocsp_url: typing.Optional[str],
        issuer_url: typing.Optional[str],
        ca_crl_url: typing.List[str],
        ca_ocsp_url: typing.Optional[str],
        ca_issuer_url: typing.Optional[str],
        permit_name: typing.Optional[typing.Iterable[x509.GeneralName]],
        exclude_name: typing.Optional[typing.Iterable[x509.GeneralName]],
        caa: str,
        website: str,
        tos: str,
        **options: typing.Any,
    ) -> None:
        if not os.path.exists(ca_settings.CA_DIR):  # pragma: no cover
            # TODO: set permissions
            os.makedirs(ca_settings.CA_DIR)

        # In case of CAs, we silently set the expiry date to that of the parent CA if the user specified a
        # number of days that would make the CA expire after the parent CA.
        #
        # The reasoning is simple: When issuing the child CA, the default is automatically after that of the
        # parent if it wasn't issued on the same day.
        if parent and timezone.now() + expires > parent.expires:
            expires = parent.expires  # type: ignore[assignment]
        if parent and not parent.allows_intermediate_ca:
            raise CommandError("Parent CA cannot create intermediate CA due to pathlen restrictions.")
        if not parent and ca_crl_url:
            raise CommandError("CRLs cannot be used to revoke root CAs.")
        if not parent and ca_ocsp_url:
            raise CommandError("OCSP cannot be used to revoke root CAs.")

        # We require a valid common name
        common_name = next((attr.value for attr in subject if attr.oid == NameOID.COMMON_NAME), False)
        if not common_name:
            raise CommandError("Subject must contain a common name (/CN=...).")

        # See if we can work with the private key
        if parent:
            self.test_private_key(parent, parent_password)

        subject = sort_name(subject)

        issuer_alternative_name = options[EXTENSION_KEYS[x509.IssuerAlternativeName.oid]]

        kwargs = {}
        for opt in ["path", "default_hostname"]:
            if options[opt] is not None:
                kwargs[opt] = options[opt]

        if ca_settings.CA_ENABLE_ACME:  # pragma: no branch; never False because parser throws error already
            # These settings are only there if ACME is enabled
            for opt in ["acme_enabled", "acme_requires_contact"]:
                if options[opt] is not None:
                    kwargs[opt] = options[opt]

        try:
            ca = CertificateAuthority.objects.init(
                name=name,
                subject=subject,
                expires=expires,
                algorithm=algorithm,
                parent=parent,
                pathlen=pathlen,
                issuer_url=issuer_url,
                issuer_alt_name=issuer_alternative_name,
                crl_url=crl_url,
                ocsp_url=ocsp_url,
                ca_issuer_url=ca_issuer_url,
                ca_crl_url=ca_crl_url,
                ca_ocsp_url=ca_ocsp_url,
                permitted_subtrees=permit_name,
                excluded_subtrees=exclude_name,
                password=password,
                parent_password=parent_password,
                ecc_curve=ecc_curve,
                key_type=key_type,
                key_size=key_size,
                caa=caa,
                website=website,
                terms_of_service=tos,
                **kwargs,
            )
        except Exception as ex:
            raise CommandError(ex) from ex

        # Generate OCSP keys and cache CRLs
        run_task(generate_ocsp_key, serial=ca.serial, password=password)
        run_task(cache_crl, serial=ca.serial, password=password)
