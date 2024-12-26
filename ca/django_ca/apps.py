# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca. If not, see
# <http://www.gnu.org/licenses/>.

"""Default Django app configuration.

.. seealso:: https://docs.djangoproject.com/en/dev/ref/applications/
"""

from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class DjangoCAConfig(AppConfig):
    """Standard configuration.

    .. seealso:: https://docs.djangoproject.com/en/dev/ref/applications/
    """

    default_auto_field = "django.db.models.BigAutoField"
    name = "django_ca"
    verbose_name = _("Certificate Authority")

    def ready(self) -> None:
        # pylint: disable=import-outside-toplevel  # that's how checks work

        from django_ca import checks  # NOQA: F401  # import already registers the checks

        # log_settings_files = os.environ.get("CA_LOG_SETTINGS_FILES", "").lower()
        # if log_settings_files in ("1", "true", "yes"):
        #     import logging
        #
        #     from django.conf import settings
        #
        #     log = logging.getLogger("django_ca")
        #     log.info(
        #         "Loaded settings from files: %s",
        #         ", ".join(str(path) for path in getattr(settings, "SETTINGS_FILES", [])),
        #     )
