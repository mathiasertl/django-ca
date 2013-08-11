import sys

from datetime import datetime

from OpenSSL import crypto

from django.core.management.base import BaseCommand
from django.utils import six

from certificate.models import Certificate

DATE_FMT = '%Y%m%d%H%M%SZ'


class Command(BaseCommand):
    args = '<id>'
    help = 'View a given certificate by ID'

    def handle(self, *args, **options):
        if len(args) != 1:
            self.stderr.write(
                "Please give exactly one ID (first colum of list command)")
            sys.exit()

        try:
            cert = Certificate.objects.get(pk=args[0])
        except Certificate.DoesNotExist:
            self.stderr.write('Certificate with given ID not found.')
            sys.exit(1)
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert.pub)

        print('Common Name: %s' % cert.cn)

        for i in range(0, x509.get_extension_count()):
            ext = x509.get_extension(i)
            if ext.get_short_name() == 'subjectAltName':
                names = ext.get_data().lstrip('0D\x82\x0f').split('\x82\x0f')
                print('Alternative Names: %s' % ', '.join(names))

                break

        emails = [w.email for w in cert.watchers.all()]
        print('Watchers: %s' % ', '.join(emails))

        validFrom = datetime.strptime(x509.get_notBefore(), DATE_FMT)
        validUntil = datetime.strptime(x509.get_notAfter(), DATE_FMT)

        print('Valid from: %s' % validFrom.strftime('%Y-%m-%d %H:%M'))
        print('Valid until: %s' % validUntil.strftime('%Y-%m-%d %H:%M'))

        print('Digest:')
        print('    md5: %s' % x509.digest('md5'))
        print('    sha1: %s' % x509.digest('sha1'))
        print('    sha256: %s' % x509.digest('sha256'))
        print('    sha512: %s' % x509.digest('sha512'))
