from django.apps import AppConfig

from django.utils.translation import ugettext_lazy as _

class DjangoCAConfig(AppConfig):
    name = 'django_ca'
    verbose_name = _('Certificate Authority')
