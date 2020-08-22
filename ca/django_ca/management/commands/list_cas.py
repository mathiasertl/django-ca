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

from ...models import CertificateAuthority
from ...utils import add_colons
from ..base import BaseCommand


class Command(BaseCommand):
    help = 'List available certificate authorities.'

    def add_arguments(self, parser):
        parser.add_argument('-t', '--tree', default=False, action='store_true',
                            help="Output data in a tree view.")

    def qs(self, qs):
        return qs.order_by('expires', 'name')

    def list_ca(self, ca, indent=''):
        text = '%s%s - %s' % (indent, add_colons(ca.serial), ca.name)
        if ca.enabled is False:
            text += ' (disabled)'

        self.stdout.write(text)

    def list_children(self, ca, left, indent=''):
        children = list(enumerate(self.qs(ca.children.all()), 1))
        for index, child in children:
            if index == len(children):  # last element
                self.list_ca(child, indent=indent + '└───')
            else:
                self.list_ca(child, indent=indent + '│───')

            children_left = len(children) - index
            if children_left:
                child_indent = indent + '│   '
            else:
                child_indent = indent + '    '

            self.list_children(child, children_left, child_indent)

    def handle(self, **options):
        if options['tree']:
            cas = list(enumerate(self.qs(CertificateAuthority.objects.filter(parent__isnull=True)), 1))
            for index, ca in cas:
                self.list_ca(ca)
                self.list_children(ca, left=(len(cas) - index))
        else:
            for ca in self.qs(CertificateAuthority.objects.all()):
                self.list_ca(ca)
