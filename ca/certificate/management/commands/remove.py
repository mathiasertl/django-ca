import sys

from datetime import datetime

from django.core.management.base import BaseCommand

from certificate.models import Certificate


class Command(BaseCommand):
    args = '<id>'
    help = 'Remove a certificate by ID (first column of list command)'

    def handle(self, *args, **options):
        if len(args) != 1:
            self.stderr.write(
                "Please give exactly one ID (first colum of list command)")
            sys.exit()
        try:
            cert = Certificate.objects.get(pk=args[0])
            cert.delete()
        except Certificate.DoesNotExist:
            self.stderr.write('Certificate with given ID not found.')
            sys.exit(1)
