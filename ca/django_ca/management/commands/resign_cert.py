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

"""Management command to resign an existing certificate.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

import typing
from datetime import timedelta

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from django.core.management.base import CommandError, CommandParser

from ... import ca_settings
from ...constants import EXTENSION_KEYS
from ...management.actions import CertificateAction
from ...management.base import BaseSignCommand
from ...models import Certificate, CertificateAuthority, Watcher
from ...profiles import Profile, profiles


class Command(BaseSignCommand):  # pylint: disable=missing-class-docstring
    help = f"""Sign a CSR and output signed certificate. The defaults depend on the configured
default profile, currently {ca_settings.CA_DEFAULT_PROFILE}."""

    add_extensions_help = "Override certificate extensions."
    subject_help = "Override subject for new certificate."

    def add_arguments(self, parser: CommandParser) -> None:
        self.add_base_args(parser, no_default_ca=True)
        self.add_profile(parser, """Use given profile to determine certificate expiry.""")
        parser.add_argument(
            "cert", action=CertificateAction, allow_revoked=True, help="The certificate to resign."
        )

    def get_profile(self, profile: typing.Optional[str], cert: Certificate) -> Profile:
        """Get requested profile based on command line and given certificate."""
        if profile is not None:
            return profiles[profile]
        if cert.profile == "":
            return profiles[None]

        try:
            return profiles[cert.profile]
        except KeyError:
            # Occurs if the certificate specifies a profile which has since been removed from settings
            raise CommandError(  # pylint: disable=raise-missing-from
                f'Profile "{cert.profile}" for original certificate is no longer defined, please set one via the command line.'  # NOQA: E501
            )

    def handle(
        self,
        cert: Certificate,
        ca: typing.Optional[CertificateAuthority],
        subject: typing.Optional[x509.Name],
        expires: typing.Optional[timedelta],
        watch: typing.List[str],
        password: typing.Optional[bytes],
        profile: typing.Optional[str],
        **options: typing.Any,
    ) -> None:
        if not ca:
            ca = cert.ca

        profile_obj = self.get_profile(profile, cert)
        self.test_options(ca=ca, password=password, expires=expires, profile=profile_obj, **options)

        # get list of watchers
        if watch:
            watchers = [Watcher.from_addr(addr) for addr in watch]
        else:
            watchers = list(cert.watchers.all())

        if subject is None:
            subject = cert.subject

        if not options[EXTENSION_KEYS[ExtensionOID.KEY_USAGE]]:
            key_usage = cert.x509_extensions.get(ExtensionOID.KEY_USAGE)
        else:
            key_usage = options[EXTENSION_KEYS[ExtensionOID.KEY_USAGE]]

        if not options[EXTENSION_KEYS[ExtensionOID.EXTENDED_KEY_USAGE]]:
            ext_key_usage = cert.x509_extensions.get(ExtensionOID.EXTENDED_KEY_USAGE)
        else:
            ext_key_usage = options[EXTENSION_KEYS[ExtensionOID.EXTENDED_KEY_USAGE]]

        if not options[EXTENSION_KEYS[ExtensionOID.TLS_FEATURE]]:
            tls_feature = cert.x509_extensions.get(ExtensionOID.TLS_FEATURE)
        else:
            tls_feature = options[EXTENSION_KEYS[ExtensionOID.TLS_FEATURE]]

        kwargs = {
            "algorithm": options["algorithm"],
            "extensions": [],
            "password": password,
            "cn_in_san": False,  # we already copy the SAN/CN from the original cert
        }

        for ext in [key_usage, ext_key_usage, tls_feature]:
            if ext is not None:
                kwargs["extensions"].append(ext)

        if not options[EXTENSION_KEYS[ExtensionOID.SUBJECT_ALTERNATIVE_NAME]]:
            san = cert.x509_extensions.get(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        else:
            san = options[EXTENSION_KEYS[ExtensionOID.SUBJECT_ALTERNATIVE_NAME]]
        kwargs["extensions"].append(san)

        if not subject.get_attributes_for_oid(NameOID.COMMON_NAME) and not san:
            raise CommandError("Must give at least a CN in --subject or one or more --alt arguments.")

        try:
            cert = Certificate.objects.create_cert(
                ca=ca, csr=cert.csr.loaded, profile=profile_obj, expires=expires, subject=subject, **kwargs
            )
        except Exception as ex:
            raise CommandError(ex) from ex

        cert.watchers.add(*watchers)

        if options["out"]:
            with open(options["out"], "w", encoding="ascii") as stream:
                stream.write(cert.pub.pem)
        else:
            self.stdout.write(cert.pub.pem)
