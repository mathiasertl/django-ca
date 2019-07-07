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

import os
import shutil

from django.core.files.storage import FileSystemStorage
from django.core.management.base import CommandError

from ...models import CertificateAuthority
from ...utils import ca_storage
from ..base import BaseCommand


class Command(BaseCommand):
    help = """Migrate CA paths to a relative path to enable new storage system. See
https://django-ca.readthedocs.io/en/1.12.0/update.html#migrate-cas.

By default, this command will only update the path to the private key in the database to a relative path if
the change does not require moving the private key. If you have stored private keys outside of your CA_DIR,
pass the --force parameter."""

    def add_arguments(self, parser):
        parser.add_argument('serial', nargs='*',
                            help="Only migrate the given CAs. If not given, migrate all CAs.")
        parser.add_argument('--force', default=False, action='store_true',
                            help="Move private keys if they are outside the expected path.")
        parser.add_argument('--dry', default=False, action='store_true',
                            help="Do not take any action, only output expected actions.")

    def handle(self, **options):
        serials = options['serial']
        dry = options['dry']

        if not isinstance(ca_storage, FileSystemStorage):
            raise CommandError('CA_FILE_STORAGE is not a subclass of FileSystemStorage.')
        dest = os.path.realpath(ca_storage.location)

        if not serials:
            serials = CertificateAuthority.objects.all().order_by('serial').values_list('serial', flat=True)

        for serial in serials:
            try:
                ca = CertificateAuthority.objects.get(serial=serial)
            except CertificateAuthority.DoesNotExist:
                self.stderr.write(self.style.ERROR('%s: Unknown CA.' % serial))
                continue

            if not os.path.isabs(ca.private_key_path):
                self.stdout.write(self.style.SUCCESS('%s: Already migrated.' % serial))
                continue

            path = os.path.realpath(ca.private_key_path)
            if path.startswith(dest):
                name = os.path.relpath(path, start=dest)
                self.stdout.write(self.style.SUCCESS(
                    '%s: Updating %s to %s.' % (serial, ca.private_key_path, name)))
                if dry is False:
                    ca.private_key_path = os.path.relpath(path, start=dest)
                    ca.save()
            elif options['force']:
                if not os.path.exists(ca.private_key_path):
                    self.stderr.write(self.style.ERROR(
                        '%s: %s: File not found.' % (ca.serial, ca.private_key_path)))
                    continue

                name = ca_storage.get_available_name(os.path.basename(ca.private_key_path))
                dest_path = ca_storage.path(name)
                self.stdout.write(self.style.SUCCESS(
                    '%s: Move %s to %s.' % (ca.serial, ca.private_key_path, name)
                ))

                if dry is False:
                    shutil.move(ca.private_key_path, dest_path)
                    ca.private_key_path = name
                    ca.save()
            else:
                self.stderr.write(self.style.WARNING(
                    '%s: %s is not in a subdir of %s. Use --force to move files.' % (
                        ca.serial, ca.private_key_path, dest))
                )
