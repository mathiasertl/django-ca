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

from datetime import timedelta
from typing import Any, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.x509.oid import NameOID

from django.core.management.base import CommandError, CommandParser

from django_ca import ca_settings
from django_ca.constants import EXTENSION_KEYS
from django_ca.management.actions import CertificateAction
from django_ca.management.base import BaseSignCommand
from django_ca.models import Certificate, CertificateAuthority, Watcher
from django_ca.profiles import Profile, profiles


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

    def get_profile(self, profile: Optional[str], cert: Certificate) -> Profile:
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
        ca: Optional[CertificateAuthority],
        subject: Optional[x509.Name],
        expires: Optional[timedelta],
        watch: List[str],
        password: Optional[bytes],
        profile: Optional[str],
        algorithm: Optional[hashes.HashAlgorithm],
        **options: Any,
    ) -> None:
        if not ca:
            ca = cert.ca

        # See if we can work with the private key
        ca_key = self.test_private_key(ca, password)

        profile_obj = self.get_profile(profile, cert)
        self.test_options(ca=ca, password=password, expires=expires, profile=profile_obj, **options)

        # get list of watchers
        if watch:
            watchers = [Watcher.from_addr(addr) for addr in watch]
        else:
            watchers = list(cert.watchers.all())

        if subject is None:
            subject = cert.subject

        if algorithm is None:
            if isinstance(ca_key, dsa.DSAPrivateKey):
                algorithm = ca_settings.CA_DSA_SIGNATURE_HASH_ALGORITHM
            else:
                algorithm = ca_settings.CA_DIGEST_ALGORITHM

        extensions: List[x509.Extension[x509.ExtensionType]] = []
        have_san = False
        for ext_type in self.sign_extensions:
            if not options[EXTENSION_KEYS[ext_type.oid]]:
                ext = cert.x509_extensions.get(ext_type.oid)
            else:
                ext = options[EXTENSION_KEYS[ext_type.oid]]

            if ext is not None:
                if ext_type == x509.SubjectAlternativeName:
                    have_san = True
                extensions.append(ext)

        if not subject.get_attributes_for_oid(NameOID.COMMON_NAME) and have_san is False:
            raise CommandError("Must give at least a CN in --subject or one or more --alt arguments.")

        try:
            cert = Certificate.objects.create_cert(
                ca=ca,
                csr=cert.csr.loaded,
                profile=profile_obj,
                expires=expires,
                subject=subject,
                algorithm=algorithm,
                extensions=extensions,
                password=password,
                cn_in_san=False,  # we already copy the SAN/CN from the original cert
            )
        except Exception as ex:
            raise CommandError(ex) from ex

        cert.watchers.add(*watchers)

        if options["out"]:
            with open(options["out"], "w", encoding="ascii") as stream:
                stream.write(cert.pub.pem)
        else:
            self.stdout.write(cert.pub.pem)
