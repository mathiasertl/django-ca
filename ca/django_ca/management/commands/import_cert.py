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

import argparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from django.core.management.base import CommandError

from ...models import Certificate
from ..base import BaseCommand


class Command(BaseCommand):
    help = """Import an existing certificate.

The authority that that signed the certificate must exist in the database."""

    def add_arguments(self, parser):
        self.add_ca(parser, allow_disabled=False)
        parser.add_argument('pub', help='Path to the public key (PEM or DER format).',
                            type=argparse.FileType('rb'))

    def handle(self, pub, **options):
        pub_data = pub.read()

        try:  # close reader objects (otherwise we get a ResourceWarning)
            pub.close()
        except Exception:  # pragma: no cover
            pass

        # load public key
        try:
            pub_loaded = x509.load_pem_x509_certificate(pub_data, default_backend())
        except Exception:
            try:
                pub_loaded = x509.load_der_x509_certificate(pub_data, default_backend())
            except Exception:
                raise CommandError('Unable to load public key.')

        cert = Certificate(ca=options['ca'])
        cert.x509 = pub_loaded
        cert.save()
