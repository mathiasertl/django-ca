from django.conf import settings
from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from django.utils import six

from certificate_authority.models import Certificate


class Command(BaseCommand):
    help = "Sign a CSR and output signed certificate."

    def add_arguments(self, parser):
        parser.add_argument(
            '--days', default=720, type=int,
            help='Sign the certificate for DAYS days (default: %(default)s)')
        parser.add_argument(
            '--algorithm',
            help='Algorithm to use (default: The DIGEST_ALGORITHM setting in settings.py)')
        parser.add_argument(
            '--csr', metavar='FILE',
            help='The path to the certificate to sign, if ommitted, you will be be prompted.')
        parser.add_argument(
            '--alt', metavar='DOMAIN', action='append', default=[],
            help='Add a subjectAltName to the certificate (may be given multiple times)')
        parser.add_argument(
            '--watch', metavar='EMAIL', action='append', default=[],
            help='Email EMAIL when this certificate expires (may be given multiple times)')
        parser.add_argument(
            '--out', metavar='FILE',
            help='Save signed certificate to FILE. If omitted, print to stdout.')
        parser.add_argument(
            '--key-usage', default=','.join(settings.CA_KEY_USAGE), metavar='NAMES',
            help="Override keyUsage attribute (default: CA_KEY_USAGE setting: %(default)s).")
        parser.add_argument(
            '--ext-key-usage', default=','.join(settings.CA_EXT_KEY_USAGE), metavar='NAMES',
            help="Override keyUsage attribute (default: CA_EXT_KEY_USAGE setting: %(default)s).")
        parser.add_argument(
            '--ocsp', default=False, action='store_true',
            help="Issue a certificate for an OCSP server.")

    def handle(self, *args, **options):
        if options['csr'] is None:
            print('Please paste the CSR:')
            csr = ''
            while not csr.endswith('-----END CERTIFICATE REQUEST-----\n'):
                csr += '%s\n' % six.moves.input()
            csr = csr.strip()
        else:
            csr = open(options['csr']).read()

        watchers = []
        for addr in options['watch']:
            watchers.append(User.objects.get_or_create(
                email=addr, defaults={'username': addr})[0])

        if not options['ocsp']:
            key_usage = options['key_usage'].split(',')
            ext_key_usage = options['ext_key_usage'].split(',')
        else:
            key_usage = (str('nonRepudiation'), str('digitalSignature'), str('keyEncipherment'), )
            ext_key_usage = (str('OCSPSigning'), )

        cert = Certificate.objects.from_csr(
            csr, subjectAltNames=options['alt'], days=options['days'],
            algorithm=options['algorithm'], watchers=watchers, key_usage=key_usage,
            ext_key_usage=ext_key_usage)

        if options['out']:
            with open(options['out'], 'w') as f:
                f.write(cert.pub.decode('utf-8'))
        else:
            print(cert.pub)
