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

from django.core.management.base import CommandError
from django.core.management.base import CommandParser

from ... import ca_settings
from ...extensions import OID_DEFAULT_CRITICAL
from ...extensions import OID_TO_KEY
from ...extensions import ExtendedKeyUsage
from ...extensions import KeyUsage
from ...extensions import SubjectAlternativeName
from ...extensions import TLSFeature
from ...management.actions import CertificateAction
from ...management.base import BaseSignCommand
from ...models import Certificate
from ...models import CertificateAuthority
from ...models import Watcher
from ...profiles import Profile
from ...profiles import profiles
from ...subject import Subject


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

    def handle(  # type: ignore[override]
        self,
        cert: Certificate,
        ca: typing.Optional[CertificateAuthority],
        subject: typing.Optional[Subject],
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
            subject = Subject(cert.subject)

        if not options[KeyUsage.key]:
            key_usage = cert.key_usage
        else:
            key_usage = options[KeyUsage.key]

        if not options[ExtendedKeyUsage.key]:
            ext_key_usage = cert.extended_key_usage
        else:
            ext_key_usage = options[ExtendedKeyUsage.key]

        if not options[TLSFeature.key]:
            tls_feature = cert.tls_feature
        else:
            tls_feature = options[TLSFeature.key]

        kwargs = {
            "algorithm": options["algorithm"],
            "extensions": {},
            "password": password,
            "subject": subject,
            "cn_in_san": False,  # we already copy the SAN/CN from the original cert
        }

        for ext in [key_usage, ext_key_usage, tls_feature]:
            if ext is not None:
                kwargs["extensions"][ext.key] = ext

        if not options[OID_TO_KEY[SubjectAlternativeName.oid]]:
            san = cert._x509_extensions.get(SubjectAlternativeName.oid)  # pylint: disable=protected-access
        else:
            san = x509.Extension(
                oid=SubjectAlternativeName.oid,
                critical=OID_DEFAULT_CRITICAL[SubjectAlternativeName.oid],
                value=options[OID_TO_KEY[SubjectAlternativeName.oid]],
            )
        kwargs["extensions"][OID_TO_KEY[SubjectAlternativeName.oid]] = san

        if "CN" not in kwargs["subject"] and not san:
            raise CommandError("Must give at least a CN in --subject or one or more --alt arguments.")

        try:
            cert = Certificate.objects.create_cert(
                ca=ca, csr=cert.csr.loaded, expires=expires, profile=profile_obj, **kwargs
            )
        except Exception as ex:
            raise CommandError(ex) from ex

        cert.watchers.add(*watchers)

        if options["out"]:
            with open(options["out"], "w", encoding="ascii") as stream:
                stream.write(cert.pub.pem)
        else:
            self.stdout.write(cert.pub.pem)
