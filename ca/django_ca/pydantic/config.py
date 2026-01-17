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

"""Application configuration for django-ca."""

from typing import Any

from pydantic import Field


class ProjectSettingsModelMixin:
    """Mixin for models that contain project settings."""

    ALLOWED_HOSTS: list[str] = Field(default_factory=list)
    CACHES: dict[str, dict[str, Any]] = Field(default_factory=dict)
    CELERY_BEAT_SCHEDULE: dict[str, dict[str, Any]] = Field(default_factory=dict)
    DATABASES: dict[str, dict[str, Any]] = Field(default_factory=dict)
    EXTEND_CELERY_BEAT_SCHEDULE: dict[str, dict[str, Any]] = Field(
        default_factory=dict,
        examples=[
            {
                "generate-crls": {"task": "django_ca.tasks.generate_crls", "schedule": 3600},
                "custom-task": {"task": "myapp.tasks.custom_task", "schedule": 300},
            }
        ],
    )
    EXTEND_INSTALLED_APPS: list[str] = Field(
        default_factory=list, examples=[["myapp", "otherapp.apps.OtherAppConfig"]]
    )
    EXTEND_URL_PATTERNS: list[dict[str, Any]] = Field(default_factory=list)
    LOG_FORMAT: str = Field(
        description="The default log format of log messages. "
        "This setting has no effect if you define the ``LOGGING`` setting."
    )
    STORAGES: dict[str, dict[str, Any]] = Field(default_factory=dict)
