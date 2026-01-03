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

"""Messages for Celery tasks."""

from pydantic import Field

from django_ca.celery import CeleryMessageModel
from django_ca.pydantic.type_aliases import Serial
from django_ca.typehints import JSON


class CacheCrlCeleryMessage(CeleryMessageModel):
    """Parameters for ``django_ca.tasks.cache_crl``."""

    serial: Serial
    key_backend_options: dict[str, JSON] = Field(default_factory=dict)
