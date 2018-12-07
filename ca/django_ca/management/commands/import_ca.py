# -*- coding: utf-8 -*-
#
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
import os

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat

from django.core.management.base import CommandError
from django.core.files.storage import default_storage
from django.utils import six

from ... import ca_settings
from ...models import CertificateAuthority
from ...utils import write_private_file
from ..base import BaseCommand
from ..base import CertificateAuthorityDetailMixin
from ..base import PasswordAction

if six.PY2:  # pragma: only py2
    from ...utils import PermissionError


class Command(BaseCommand, CertificateAuthorityDetailMixin):
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

    def handle(self, name, key, pem, **options):
        try:
            local_path = default_storage.path(ca_settings.CA_DIR)
            if not os.path.exists(local_path):  # pragma: no cover
                # TODO: set permissions
                os.makedirs(local_path)
        except NotImplementedError:
            # Using external storage. S3 and Minio manage path creation
            pass

        password = options['password']
        import_password = options['import_password']
        parent = options['parent']
        pem_data = pem.read()
        key_data = key.read()
        crl_url = '\n'.join(options['crl_url'])

        try:  # close reader objects (otherwise we get a ResourceWarning)
            key.close()
            pem.close()
        except Exception:  # pragma: no cover
            pass

        ca = CertificateAuthority(name=name, parent=parent, issuer_url=options['issuer_url'],
                                  issuer_alt_name=options['issuer_alt_name'], crl_url=crl_url)

        # load public key
        try:
            pem_loaded = x509.load_pem_x509_certificate(pem_data, default_backend())
        except Exception:
            try:
                pem_loaded = x509.load_der_x509_certificate(pem_data, default_backend())
            except Exception:
                raise CommandError('Unable to load public key.')
        ca.x509 = pem_loaded
        ca.private_key_path = os.path.join(ca_settings.CA_DIR, '%s.key' % ca.serial)

        # load private key
        try:
            key_loaded = serialization.load_pem_private_key(key_data, import_password, default_backend())
        except Exception:
            try:
                key_loaded = serialization.load_der_private_key(key_data, import_password, default_backend())
            except Exception:
                raise CommandError('Unable to load private key.')

        if password is None:
            encryption = serialization.NoEncryption()
        else:
            encryption = serialization.BestAvailableEncryption(password)

        # write private key to file
        pem = key_loaded.private_bytes(encoding=Encoding.PEM,
                                       format=PrivateFormat.TraditionalOpenSSL,
                                       encryption_algorithm=encryption)

        try:
            write_private_file(ca.private_key_path, pem)
        except PermissionError:
            perm_denied = '%s: Permission denied: Could not open file for writing' % ca.private_key_path
            raise CommandError(perm_denied)

        # Only save CA to database if we loaded all data and copied private key
        ca.save()
