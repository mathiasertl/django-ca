from datetime import datetime
from optparse import make_option

from django.core.management.base import BaseCommand

from certificate.models import Certificate


class Command(BaseCommand):
    help = "List all certificates"

    option_list = BaseCommand.option_list + (
        make_option('--expired',
            default=False,
            action='store_true',
            help='Also list expired certificates'
        ),
    )

    def handle(self, *args, **options):
        certs = Certificate.objects.all()

        if not options['expired']:
            certs = certs.filter(expires__gt=datetime.now())

        for cert in certs:
            print('%s: %s (expires: %s)' % (cert.pk, cert.cn,
                                            cert.expires.strftime('%Y-%m-%d')))
