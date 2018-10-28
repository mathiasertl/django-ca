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
from ...subject import Subject


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

        if options.get('subject'):
            subject = Subject(options['subject'])
        else:
            subject = cert.subject

        key_usage = options.get('key_usage', cert.keyUsage)
        ext_key_usage = options.get('ext_key_usage', cert.extendedKeyUsage)
        tls_feature = options.get('tls_feature', cert.TLSFeature)

        kwargs = {
            'subject': subject,
            'password': options['password'],
            'csr_format': Encoding.PEM,
            'keyUsage': key_usage,
            'extendedKeyUsage': ext_key_usage,
            'tls_feature': tls_feature,
            'algorithm': options.get('algorithm', cert.algorithm),
            'expires': options['expires'],
            'subjectAltName': options.get('alt', cert.subjectAltName()[1]),
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
