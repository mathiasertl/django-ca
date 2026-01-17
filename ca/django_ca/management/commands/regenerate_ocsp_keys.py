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

"""**Deprecated.** Management command to generate OCSP keys.

.. deprecated:: 3.0.0

    Use `manage.py generate_ocsp_keys` instead.
"""

from typing import Any

from django_ca.management.commands import generate_ocsp_keys


class Command(generate_ocsp_keys.Command):  # noqa: D101
    help = "(Deprecated) Generate OCSP keys. Use generate_ocsp_keys instead."

    def handle(self, *args: Any, **options: Any) -> None:
        self.stderr.write(
            self.style.WARNING(
                "Warning: This command is deprecated. Please use generate_ocsp_keys instead. "
                "This alias will be removed in django_ca~=3.2.0."
            )
        )
        super().handle(*args, **options)
