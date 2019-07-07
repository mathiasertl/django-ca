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
# see <http://www.gnu.org/licenses/>

import os
import shutil
import tempfile

import six

from ..models import CertificateAuthority
from ..utils import ca_storage
from .base import DjangoCAWithCATestCase
from .base import override_tmpcadir

if six.PY2:  # pragma: only py2
    from mock import patch

else:  # pragma: only py3
    from unittest.mock import patch


class MigrateCATestCase(DjangoCAWithCATestCase):
    def setUp(self):
        super(MigrateCATestCase, self).setUp()
        self.ca = self.cas['root']

    @override_tmpcadir()
    def test_migrate(self):
        orig_path = self.ca.private_key_path
        self.assertTrue(self.ca.key_exists)
        self.ca.private_key_path = os.path.join(ca_storage.location, self.ca.private_key_path)
        self.ca.save()
        stdout, stderr = self.cmd('migrate_ca', self.ca.serial, no_color=True)
        self.assertEqual(stdout, '%s: Updating %s to %s.\n' % (
            self.ca.serial, self.ca.private_key_path, orig_path))
        self.assertEqual(stderr, '')

        ca = CertificateAuthority.objects.get(serial=self.ca.serial)
        self.assertEqual(orig_path, ca.private_key_path)
        self.assertTrue(ca.key_exists)

    @override_tmpcadir()
    def test_already_migrated(self):
        old_path = self.ca.private_key_path
        stdout, stderr = self.cmd('migrate_ca', self.ca.serial, no_color=True)
        self.assertEqual(stdout, '%s: Already migrated.\n' % self.ca.serial)
        self.assertEqual(stderr, '')
        self.assertEqual(old_path, CertificateAuthority.objects.get(serial=self.ca.serial).private_key_path)

    @override_tmpcadir()
    def test_dry(self):
        orig_path = self.ca.private_key_path
        self.assertTrue(self.ca.key_exists)
        self.ca.private_key_path = abs_path = os.path.join(ca_storage.location, self.ca.private_key_path)
        self.ca.save()

        stdout, stderr = self.cmd('migrate_ca', self.ca.serial, dry=True, no_color=True)
        self.assertEqual(stdout, '%s: Updating %s to %s.\n' % (
            self.ca.serial, self.ca.private_key_path, orig_path))

        # path hasn't changed
        self.assertEqual(abs_path, CertificateAuthority.objects.get(serial=self.ca.serial).private_key_path)

    @override_tmpcadir()
    def test_force_dry(self):
        orig_path = self.ca.private_key_path
        self.assertTrue(self.ca.key_exists)
        source_dir = tempfile.mkdtemp()

        try:
            # move private key outside of ca_storage
            self.ca.private_key_path = abs_path = os.path.join(source_dir, self.ca.private_key_path)
            self.ca.save()
            shutil.move(ca_storage.path(orig_path), self.ca.private_key_path)
            self.assertTrue(self.ca.key_exists)  # just make sure we did the correct thing above

            stdout, stderr = self.cmd('migrate_ca', self.ca.serial, no_color=True, dry=True, force=True)
            self.assertEqual(stdout, '%s: Move %s to %s.\n' % (
                self.ca.serial, self.ca.private_key_path, orig_path
            ))
            self.assertEqual(stderr, '')

            new_ca = CertificateAuthority.objects.get(serial=self.ca.serial)
            self.assertEqual(abs_path, new_ca.private_key_path)
            self.assertTrue(new_ca.key_exists)
        finally:
            shutil.rmtree(source_dir)

    @override_tmpcadir()
    def test_outside_ca(self):
        orig_path = self.ca.private_key_path
        self.assertTrue(self.ca.key_exists)
        source_dir = tempfile.mkdtemp()

        try:
            # move private key outside of ca_storage
            self.ca.private_key_path = os.path.join(source_dir, self.ca.private_key_path)
            self.ca.save()
            shutil.move(ca_storage.path(orig_path), self.ca.private_key_path)
            self.assertTrue(self.ca.key_exists)  # just make sure we did the correct thing above

            stdout, stderr = self.cmd('migrate_ca', self.ca.serial, no_color=True)
            self.assertEqual(stdout, '')
            self.assertEqual(stderr, '%s: %s is not in a subdir of %s. Use --force to move files.\n' % (
                self.ca.serial, self.ca.private_key_path, ca_storage.location
            ))

            new_ca = CertificateAuthority.objects.get(serial=self.ca.serial)
            self.assertEqual(self.ca.private_key_path, new_ca.private_key_path)
            self.assertTrue(new_ca.key_exists)
        finally:
            shutil.rmtree(source_dir)

    @override_tmpcadir()
    def test_force_outside_ca(self):
        orig_path = self.ca.private_key_path
        self.assertTrue(self.ca.key_exists)
        source_dir = tempfile.mkdtemp()

        try:
            # move private key outside of ca_storage
            self.ca.private_key_path = os.path.join(source_dir, self.ca.private_key_path)
            self.ca.save()
            shutil.move(ca_storage.path(orig_path), self.ca.private_key_path)
            self.assertTrue(self.ca.key_exists)  # just make sure we did the correct thing above

            stdout, stderr = self.cmd('migrate_ca', self.ca.serial, no_color=True, force=True)
            self.assertEqual(stdout, '%s: Move %s to %s.\n' % (
                self.ca.serial, self.ca.private_key_path, orig_path
            ))
            self.assertEqual(stderr, '')

            new_ca = CertificateAuthority.objects.get(serial=self.ca.serial)
            self.assertEqual(orig_path, new_ca.private_key_path)
            self.assertTrue(new_ca.key_exists)
        finally:
            shutil.rmtree(source_dir)

    @override_tmpcadir()
    def test_all_serials(self):
        stdout, stderr = self.cmd('migrate_ca', no_color=True)
        cas = sorted(self.cas.values(), key=lambda ca: ca.serial)
        self.assertEqual(stdout, '\n'.join([
            '%s: Already migrated.' % ca.serial for ca in cas
        ]) + '\n')
        self.assertEqual(stderr, '')

    @override_tmpcadir()
    def test_unknown_serial(self):
        serial = 'AA:BB:CC'
        stdout, stderr = self.cmd('migrate_ca', serial, no_color=True)
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '%s: Unknown CA.\n' % serial)

    @override_tmpcadir()
    def test_no_private_key(self):
        self.ca.private_key_path = '/non/existent/gone.pem'
        self.ca.save()

        stdout, stderr = self.cmd('migrate_ca', self.ca.serial, force=True, no_color=True)
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '%s: %s: File not found.\n' % (self.ca.serial, self.ca.private_key_path))

    @override_tmpcadir()
    def test_unsupported_storage(self):
        with patch('django_ca.management.commands.migrate_ca.ca_storage'):
            with self.assertCommandError(r'^CA_FILE_STORAGE is not a subclass of FileSystemStorage\.$'):
                stdout, stderr = self.cmd('migrate_ca', self.ca.serial, no_color=True)
