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

"""Start Gunicorn (installed as ``django-ca-gunicorn`` in the Docker image).

Any command-line arguments are passed to ``gunicorn``. Replaces ``gunicorn.sh`` (deprecated, will be removed
in ``django-ca==4.0.0``).
"""

import os
import sys
from pathlib import Path

from django_ca_startup import (
    copy_file,
    copy_glob,
    copy_tree_contents,
    error,
    exec_command,
    getenv,
    startup,
)

#: This directory is a Docker volume mapped to /etc/nginx/templates/ in Docker Compose.
NGINX_TEMPLATE_DIR = Path("/var/lib/django-ca/nginx/templates/")

#: Directory where NGINX templates are shipped.
NGINX_TEMPLATE_SOURCE_DIR = Path("/usr/src/django-ca/nginx/")


def sync_nginx_templates(template: str) -> None:
    """Synchronize NGINX configuration to the template dir (used by Docker Compose to update config)."""
    source = NGINX_TEMPLATE_SOURCE_DIR / f"{template}.template"
    if not os.access(source, os.R_OK):
        error(f"{template}: NGINX template not found.")

    source_include_dir = NGINX_TEMPLATE_SOURCE_DIR / "include.d"
    include_dir = NGINX_TEMPLATE_DIR / "include.d"

    include_dir.mkdir(parents=True, exist_ok=True)
    copy_file(source, NGINX_TEMPLATE_DIR / "default.conf.template")
    copy_glob(source_include_dir, "*.conf", include_dir)
    copy_glob(source_include_dir, "*.conf.template", include_dir)

    # Include http/https directories if they exist. This allows specialized containers to add their own
    # NGINX configuration.
    for subdir in ("http", "https"):
        if (source_include_dir / subdir).is_dir():
            (include_dir / subdir).mkdir(parents=True, exist_ok=True)
            copy_tree_contents(source_include_dir / subdir, include_dir / subdir)


def main() -> None:
    """Main function."""
    config_file = getenv("GUNICORN_CONFIG_FILE", "/usr/src/django-ca/gunicorn/gunicorn.conf.py")

    if not os.path.exists(config_file):
        error(f"{config_file}: No such file or directory.")

    if nginx_template := os.environ.get("NGINX_TEMPLATE"):
        sync_nginx_templates(nginx_template)

    startup()

    os.environ["GUNICORN_CMD_ARGS"] = getenv("GUNICORN_CMD_ARGS", "--bind=0.0.0.0")

    # Use exec so that gunicorn replaces this process and receives signals (e.g. SIGTERM) directly.
    exec_command(["gunicorn", "--config", config_file, *sys.argv[1:], "ca.wsgi:application"])


if __name__ == "__main__":
    main()
