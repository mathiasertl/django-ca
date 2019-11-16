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
from ...extensions import ExtendedKeyUsage
from ...extensions import KeyUsage
from ...extensions import SubjectAlternativeName
from ...extensions import TLSFeature
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
        self.add_base_args(parser, no_default_ca=True)
        parser.add_argument('cert', action=CertificateAction, allow_revoked=True,
                            help='The certificate to resign.')

    def handle(self, *args, **options):
        cert = options['cert']
        ca = options['ca']
        if not ca:
            ca = options['ca'] = cert.ca
        csr = cert.csr
        self.test_options(*args, **options)

        # get list of watchers
        if options['watch']:
            watchers = [Watcher.from_addr(addr) for addr in options['watch']]
        else:
            watchers = list(cert.watchers.all())

        if options['subject']:
            subject = options['subject']
        else:
            subject = cert.subject

        if not options[KeyUsage.key]:
            key_usage = cert.key_usage
        else:
            key_usage = options[KeyUsage.key]

        if not options[ExtendedKeyUsage.key]:
            ext_key_usage = cert.extended_key_usage
        else:
            ext_key_usage = options[ExtendedKeyUsage.key]

        if not options[TLSFeature.key]:
            tls_feature = cert.tls_feature
        else:
            tls_feature = options[TLSFeature.key]

        if not options[SubjectAlternativeName.key]:
            san = cert.subject_alternative_name
        else:
            san = options[SubjectAlternativeName.key]

        kwargs = {
            'subject': subject,
            'password': options['password'],
            'csr_format': Encoding.PEM,
            'key_usage': key_usage,
            'extended_key_usage': ext_key_usage,
            'tls_feature': tls_feature,
            'algorithm': options['algorithm'],
            'expires': options['expires'],
            'subject_alternative_name': san,
            'cn_in_san': False,
        }
        kwargs = {
            'algorithm': options['algorithm'],
            'csr_format': Encoding.PEM,
            'expires': options['expires'],
            'extensions': [],
            'password': options['password'],
            'subject': subject,
            'cn_in_san': False,  # we already copy the SAN/CN from the original cert
        }

        for ext in [key_usage, ext_key_usage, tls_feature, san]:
            if ext is not None:
                kwargs['extensions'].append(ext)

        if 'CN' not in kwargs['subject'] and not san:
            raise CommandError("Must give at least a CN in --subject or one or more --alt arguments.")

        try:
            cert = Certificate.objects.create_cert(ca=ca, csr=csr, **kwargs)
        except Exception as e:
            raise CommandError(e)

        cert.watchers.add(*watchers)

        if options['out']:
            with open(options['out'], 'w') as f:
                f.write(cert.pub)
        else:
            self.stdout.write(cert.pub)
