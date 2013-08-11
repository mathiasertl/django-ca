from optparse import make_option

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from django.utils import six

from certificate.models import Certificate


class Command(BaseCommand):
    help = "Sign a CSR and output signed certificate."

    option_list = BaseCommand.option_list + (
        make_option('--days',
            default=720,
            type='int',
            help='Sign the certificate for DAYS days (default: %default)'
        ),
        make_option(
            '--algorithm',
            help='Algorithm to use (default: The DIGEST_ALGORITHM setting in settings.py)'
        ),
        make_option(
            '--csr',
            metavar='FILE',
            help='The path to the certificate to sign, if ommitted, you will be be prompted.'
        ),
        make_option(
            '--alt',
            metavar='DOMAIN',
            action='append',
            default=[],
            help='Add a subjectAltName to the certificate (may be given multiple times)'
        ),
        make_option(
            '--watch',
            metavar='EMAIL',
            action='append',
            default=[],
            help='Email EMAIL when this certificate expires (may be given multiple times)',
        ),
        make_option(
            '--out',
            metavar='FILE',
            help='Save signed certificate to FILE. If omitted, print to stdout.'
        ),
    )

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

        cert = Certificate.objects.from_csr(
            csr, subjectAltNames=options['alt'], days=options['days'],
            algorithm=options['algorithm'], watchers=watchers)

        if options['out']:
            f = open(options['out'], 'w')
            f.write(cert.pub)
            f.close()
        else:
            print(cert.pub)
