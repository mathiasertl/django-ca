#!/usr/bin/env python3
#
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

"""Start Celery beat (installed as ``django-ca-celerybeat`` in the Docker image).

Any command-line arguments are passed to ``celery beat``. Replaces ``celerybeat.sh`` (deprecated, will be
removed in ``django-ca==4.0.0``).
"""

import sys

from django_ca_startup import exec_command, startup


def main() -> None:
    """Main function."""
    startup()
    exec_command(
        [
            "celery",
            "-A",
            "ca",
            "beat",
            "-s",
            "/var/lib/django-ca/celerybeat-schedule",
            "--pidfile",
            "/run/django-ca/celery.pid",
            *sys.argv[1:],
        ]
    )


if __name__ == "__main__":
    main()
