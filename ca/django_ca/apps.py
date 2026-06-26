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

from typing import Any

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
        from django_ca import checks  # noqa  # import already registers the checks

        from django_ca.signals import post_issue_cert, post_revoke_cert  # noqa: PLC0415

        def _on_post_issue_cert(sender: Any, cert: Any, **kwargs: Any) -> None:
            """Trigger OCSP response caching when a new certificate is issued."""
            from django_ca.celery import run_task  # noqa: PLC0415
            from django_ca.celery.messages import CacheOCSPResponseTaskArgs  # noqa: PLC0415
            from django_ca.conf import model_settings  # noqa: PLC0415
            from django_ca.tasks import cache_ocsp_response  # noqa: PLC0415

            if model_settings.CA_OCSP_RESPONSE_CACHE_EXPIRES is not None:
                run_task(cache_ocsp_response, CacheOCSPResponseTaskArgs(serial=cert.serial, ca=False))

        post_issue_cert.connect(_on_post_issue_cert)

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
