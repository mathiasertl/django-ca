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

from ...extensions import IssuerAlternativeName
from ..base import BaseCommand
from ..base import CertificateAuthorityDetailMixin


class Command(BaseCommand, CertificateAuthorityDetailMixin):
    help = 'Edit a certificate authority.'

    def add_arguments(self, parser):
        self.add_ca(parser, 'ca', allow_disabled=True)
        self.add_ca_args(parser)

        group = parser.add_mutually_exclusive_group()
        group.add_argument('--enable', action='store_true', dest='enabled', default=None,
                           help='Enable the certificate authority.')
        group.add_argument('--disable', action='store_false', dest='enabled',
                           help='Disable the certificate authority.')

    def handle(self, ca, **options):
        if options['issuer_url'] is not None:
            ca.issuer_url = options['issuer_url']
        if options[IssuerAlternativeName.key]:
            ca.issuer_alt_name = options[IssuerAlternativeName.key]
        if options['ocsp_url'] is not None:
            ca.ocsp_url = options['ocsp_url']
        if options['crl_url'] is not None:
            ca.crl_url = '\n'.join(options['crl_url'])

        if options['enabled'] is not None:
            ca.enabled = options['enabled']

        ca.save()
