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

"""Stand-alone script to monitor if a uWSGI instance is running. Used in Docker Compose."""

import json
import socket
import sys

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        s.connect(("127.0.0.1", 1717))

        data = b""
        while True:
            recv = s.recv(4096)
            data += recv
            if len(recv) < 4096:
                break
except OSError:
    print("Error connecting to stats server.")
    sys.exit(1)

parsed = json.loads(data.decode("utf-8"))
if "pid" in parsed:
    sys.exit(0)
sys.exit(1)
