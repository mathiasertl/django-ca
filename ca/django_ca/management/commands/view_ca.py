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

from ...utils import add_colons
from ...utils import ca_storage
from ..base import BaseCommand


class Command(BaseCommand):
    help = 'View details of a certificate authority.'

    def add_arguments(self, parser):
        self.add_ca(parser, arg='ca', allow_disabled=True, allow_unusable=True)

    def handle(self, ca, **options):
        try:
            path = ca_storage.path(ca.private_key_path)
        except NotImplementedError:
            # Will raise NotImplementedError if storage backend does not support path(), in which case we use
            # the relative path from the database.
            # https://docs.djangoproject.com/en/dev/ref/files/storage/#django.core.files.storage.Storage.path
            path = ca.private_key_path

        self.stdout.write('%s (%s):' % (ca.name, 'enabled' if ca.enabled else 'disabled'))
        self.stdout.write('* Serial: %s' % add_colons(ca.serial))

        if ca_storage.exists(ca.private_key_path):
            self.stdout.write('* Path to private key:\n  %s' % path)
        else:
            self.stdout.write('* Private key not available locally.')

        if ca.parent:
            self.stdout.write('* Parent: %s (%s)' % (ca.parent.name, ca.parent.serial))
        else:
            self.stdout.write('* Is a root CA.')

        children = ca.children.all()
        if children:
            self.stdout.write('* Children:')
            for child in children:
                self.stdout.write('  * %s (%s)' % (child.name, child.serial))
        else:
            self.stdout.write('* Has no children.')

        pathlen = ca.pathlen
        if pathlen is None:
            pathlen = 'unlimited'

        self.stdout.write('* Distinguished Name: %s' % ca.distinguishedName())
        self.stdout.write('* Maximum levels of sub-CAs (pathlen): %s' % pathlen)
        self.stdout.write('* HPKP pin: %s' % ca.hpkp_pin)

        self.stdout.write('')
        self.stdout.write('X509 v3 certificate extensions for CA:')

        self.print_extensions(ca)

        self.stdout.write('')
        self.stdout.write('X509 v3 certificate extensions for signed certificates:')
        self.stdout.write('* Certificate Revokation List (CRL): %s' % (ca.crl_url or None))
        self.stdout.write('* Issuer URL: %s' % (ca.issuer_url or None))
        self.stdout.write('* OCSP URL: %s' % (ca.ocsp_url or None))
        self.stdout.write('* Issuer Alternative Name: %s' % (ca.issuer_alt_name or None))
        self.stdout.write('\n%s' % ca.pub)
