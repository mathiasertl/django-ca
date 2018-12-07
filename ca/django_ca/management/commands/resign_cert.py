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

from cryptography.hazmat.primitives.serialization import Encoding

from django.core.management.base import CommandError

from ... import ca_settings
from ...management.base import BaseSignCommand
from ...management.base import CertificateAction
from ...models import Certificate
from ...models import Watcher


class Command(BaseSignCommand):
    help = """Sign a CSR and output signed certificate. The defaults depend on the configured
default profile, currently %s.""" % ca_settings.CA_DEFAULT_PROFILE

    add_extensions_help = 'TODO'
    subject_help = 'TODO'

    def add_arguments(self, parser):
        self.add_base_args(parser)
        parser.add_argument('cert', action=CertificateAction, allow_revoked=True,
                            help='The certificate to resign.')

    def handle(self, *args, **options):
        self.test_options(*args, **options)
        ca = options['ca']
        cert = options['cert']
        csr = cert.csr

        # get list of watchers
        if options['watch']:
            watchers = [Watcher.from_addr(addr) for addr in options['watch']]
        else:
            watchers = list(cert.watchers.all())

        if options['subject']:
            subject = options['subject']
        else:
            subject = cert.subject

        if options['key_usage'] is None:
            key_usage = cert.key_usage
        else:
            key_usage = options['key_usage']

        if options['ext_key_usage'] is None:
            ext_key_usage = cert.extended_key_usage
        else:
            ext_key_usage = options['ext_key_usage']

        if options['tls_feature'] is None:
            tls_feature = cert.tls_feature
        else:
            tls_feature = options['tls_feature']

        if not options['alt']:
            san = cert.subject_alternative_name
        else:
            san = options['alt']

        kwargs = {
            'subject': subject,
            'password': options['password'],
            'csr_format': Encoding.PEM,
            'key_usage': key_usage,
            'extended_key_usage': ext_key_usage,
            'tls_feature': tls_feature,
            'algorithm': options.get('algorithm', cert.algorithm),
            'expires': options['expires'],
            'subjectAltName': san,
            'cn_in_san': False,
        }

        if 'CN' not in kwargs['subject'] and not options['alt']:
            raise CommandError("Must give at least a CN in --subject or one or more --alt arguments.")

        try:
            cert = Certificate.objects.init(ca=ca, csr=csr, **kwargs)
        except Exception as e:
            raise CommandError(e)

        cert.watchers.add(*watchers)

        if options['out']:
            with open(options['out'], 'w') as f:
                f.write(cert.pub)
        else:
            self.stdout.write(cert.pub)
