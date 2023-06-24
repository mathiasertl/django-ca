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

"""Script that tests that django-ca can connect to everything it needs."""

import os
import random
import string
import sys

import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ca.settings")

try:
    django.setup()
except ModuleNotFoundError as ex:
    print(f"Error setting up Django: {ex}")
    sys.exit(1)

from django.core.cache import cache  # NOQA: E402

# pylint: disable=wrong-import-position # django_setup needs to be called first.
from ca.celery import app  # noqa: E402
from django_ca.models import CertificateAuthority  # noqa: E402

# Verify database connectivity by fetching a list of CAs. Even an empty list verifies connectivity.
list(CertificateAuthority.objects.all())

# Verify cache connectivity.
letters = string.ascii_lowercase + string.ascii_uppercase
cache_key = "".join(random.choice(letters) for i in range(10))
cache_value = "".join(random.choice(letters) for i in range(10))
cache.set(cache_key, cache_value)

retrieved_value = cache.get(cache_key)
if retrieved_value != cache_value:
    print("Retrieved cache value differs!")
    sys.exit(1)

# Verify Celery connectivity
i = app.control.inspect()  # type: ignore[attr-defined]  # mypy does not detect correct class
availability = i.ping()  # raises an exception if the broker cannot be reached
