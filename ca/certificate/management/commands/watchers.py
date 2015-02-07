import sys

from optparse import make_option

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from django.utils import six

from certificate.models import Certificate


class Command(BaseCommand):
    args = '<id>'
    help = "Add/remove watchers to a specific certificate."

    option_list = BaseCommand.option_list + (
        make_option(
            '--add',
            metavar='EMAIL',
            default=[],
            action='append',
            help='Add an email to the watchlist (may be given multiple times)'
        ),
        make_option(
            '--rm',
            metavar='EMAIL',
            default=[],
            action='append',
            help='Remove an email from the watchlist (may be given multiple times)'
        ),
    )

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

        # add users:
        add = [User.objects.get_or_create(email=e, defaults={'username': e})[0]
               for e in options['add']]
        cert.watchers.add(*add)

        # remove users:
        if options['rm']:
            cert.watchers.filter(email__in=options['rm']).delete()
