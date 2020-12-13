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

"""Management command to import a certificate authority.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-management-commands/
"""

import argparse
import os

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat

from django.core.files.base import ContentFile
from django.core.management.base import CommandError

from ... import ca_settings
from ...extensions import IssuerAlternativeName
from ...models import CertificateAuthority
from ...utils import ca_storage
from ..base import BaseCommand
from ..base import CertificateAuthorityDetailMixin
from ..base import PasswordAction


class Command(BaseCommand, CertificateAuthorityDetailMixin):  # pylint: disable=missing-class-docstring
    help = """Import an existing certificate authority.

Note that the private key will be copied to the directory configured by the CA_DIR setting."""

    def add_arguments(self, parser):
        self.add_ca(parser, '--parent',
                    help='''Make the CA an intermediate CA of the named CA. By default, this is a
                    new root CA.''', no_default=True)
        self.add_password(
            parser, help='Password used to encrypt the private key. Pass no argument to be prompted.')
        parser.add_argument('--import-password', nargs='?', action=PasswordAction, metavar='PASSWORD',
                            prompt='Password to import CA: ',
                            help='Password for the private key.')

        self.add_ca_args(parser)

        parser.add_argument('name', help='Human-readable name of the CA')
        parser.add_argument('key', help='Path to the private key (PEM or DER format).',
                            type=argparse.FileType('rb'))
        parser.add_argument('pem', help='Path to the public key (PEM or DER format).',
                            type=argparse.FileType('rb'))

    def handle(self, name, key, pem, **options):  # pylint: disable=arguments-differ
        if not os.path.exists(ca_settings.CA_DIR):
            try:
                os.makedirs(ca_settings.CA_DIR)
            except PermissionError as ex:
                pem.close()
                key.close()
                raise CommandError(
                    '%s: Could not create CA_DIR: Permission denied.' % ca_settings.CA_DIR) from ex
            # FileNotFoundError shouldn't happen, whole point of this block is to create it

        import_password = options['import_password']
        pem_data = pem.read()
        key_data = key.read()
        crl_url = '\n'.join(options['crl_url'])

        # close reader objects (otherwise we get a ResourceWarning)
        key.close()
        pem.close()

        issuer_alternative_name = options[IssuerAlternativeName.key]
        if issuer_alternative_name is None:  # pragma: no branch - no CA sets this
            issuer_alternative_name = ''

        ca = CertificateAuthority(name=name, parent=options['parent'], issuer_url=options['issuer_url'],
                                  issuer_alt_name=issuer_alternative_name, crl_url=crl_url)

        # load public key
        try:
            pem_loaded = x509.load_pem_x509_certificate(pem_data, default_backend())
        except Exception:  # pylint: disable=broad-except
            try:
                pem_loaded = x509.load_der_x509_certificate(pem_data, default_backend())
            except Exception as ex:
                raise CommandError('Unable to load public key.') from ex
        ca.x509 = pem_loaded
        ca.private_key_path = ca_storage.generate_filename('%s.key' % ca.serial.replace(':', ''))

        # load private key
        try:
            key_loaded = serialization.load_pem_private_key(key_data, import_password, default_backend())
        except Exception:  # pylint: disable=broad-except
            try:
                key_loaded = serialization.load_der_private_key(key_data, import_password, default_backend())
            except Exception as ex:
                raise CommandError('Unable to load private key.') from ex

        if options['password'] is None:
            encryption = serialization.NoEncryption()
        else:
            encryption = serialization.BestAvailableEncryption(options['password'])

        # write private key to file
        pem = key_loaded.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.TraditionalOpenSSL,
                                       encryption_algorithm=encryption)

        try:
            ca_storage.save(ca.private_key_path, ContentFile(pem))
        except PermissionError as ex:
            raise CommandError(
                '%s: Permission denied: Could not open file for writing' % ca.private_key_path) from ex

        # Only save CA to database if we loaded all data and copied private key
        ca.save()
